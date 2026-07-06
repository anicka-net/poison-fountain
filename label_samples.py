#!/usr/bin/env python3
"""Label each sample as poisoned or clean, with detailed diagnostics."""

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

SAMPLES_PATH = Path(__file__).resolve().parent / "raw_samples" / "samples.jsonl"
OUT_PATH = Path(__file__).resolve().parent / "labeled_dataset.jsonl"


def load_samples():
    lines = Path(SAMPLES_PATH).read_text().splitlines()
    samples = [json.loads(line) for line in lines]
    return samples


# ── Poison detectors ──

def detect_repetition(text: str) -> list[str]:
    """Find repeated lines that indicate contamination."""
    issues = []
    lines = text.split("\n")
    if len(lines) < 5:
        return issues
    line_counts = Counter(lines)
    for line, count in line_counts.most_common(5):
        if count > 2 and len(line) > 15:
            issues.append(f"repetition:{count}x:{line[:50]}")
    return issues


def detect_truncation(text: str) -> list[str]:
    """Check if text looks truncated."""
    issues = []
    if not text:
        return issues
    last_char = text[-1]
    # Sentence boundaries: . ! ? " ' ) ] } \n
    sentence_enders = ".!?\"')\n"
    if last_char not in sentence_enders and last_char not in "\n\r":
        issues.append("truncated:no_sentence_boundary")
    # Check for cut-off at end (last line doesn't have proper ending)
    lines = text.split("\n")
    last_line = lines[-1].strip()
    if last_line and last_line[-1] not in sentence_enders and not last_line.endswith("```") and not last_line.endswith("..."):
        issues.append("truncated:last_line_incomplete")
    return issues


def detect_encoding_issues(text: str) -> list[str]:
    issues = []
    if "\x00" in text:
        issues.append("encoding:null_bytes")
    bad = set("\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x1b")
    if any(c in text for c in bad):
        issues.append("encoding:control_chars")
    # Check for replacement characters from decoding errors
    if "\ufffd" in text:
        issues.append("encoding:replacement_chars")
    return issues


def detect_suspicious_imports(text: str) -> list[str]:
    """Check Python code for dangerous patterns."""
    if "python" not in classify_by_first_line(text):
        return []
    issues = []
    patterns = {
        "subprocess": "import:subprocess",
        "eval(": "exec:eval",
        "exec(": "exec:exec",
        "os.system": "import:os.system",
        "pickle.load": "import:pickle",
        "requests.get(": "import:requests",
        "socket.socket": "import:socket",
    }
    for pat, label in patterns.items():
        if pat in text:
            issues.append(label)
    return issues


def detect_dead_code(text: str) -> list[str]:
    """Find commented-out code blocks that look like real code."""
    if "python" not in classify_by_first_line(text):
        return []
    issues = []
    comment_blocks = re.findall(r"^\s*# .*(def |class |for |if |while |return |import ).*", text, re.MULTILINE)
    if comment_blocks:
        issues.append(f"dead_code:{len(comment_blocks)}_statements")
    return issues


def detect_infinite_loops(text: str) -> list[str]:
    if "python" not in classify_by_first_line(text):
        return []
    issues = []
    if re.search(r"while True:|while 1:|while False == False:", text):
        issues.append("pattern:infinite_loop")
    if re.search(r"for .* in .*:\s*\n\s*pass", text):
        issues.append("pattern:empty_loop")
    return issues


def detect_mixed_languages(text: str) -> list[str]:
    """Check for high ratio of non-ASCII characters."""
    total = len(text)
    if total == 0:
        return []
    non_ascii = sum(1 for c in text if ord(c) > 127)
    ratio = non_ascii / total
    issues = []
    if ratio > 0.3:
        issues.append(f"language:mixed_{ratio:.0%}_nonascii")
    return issues


def detect_broken_syntax(text: str, content_type: str) -> list[str]:
    """Check if code/text has syntax errors."""
    issues = []
    if content_type == "python":
        try:
            ast.parse(text)
        except SyntaxError as e:
            issues.append(f"syntax:python_{type(e).__name__}_{str(e).split('(')[0].strip()[:60]}")
    elif content_type == "yaml":
        try:
            yaml.safe_load(text)
        except Exception as e:
            issues.append(f"syntax:yaml_{type(e).__name__}_{str(e).split('\n')[0][:60]}")
    elif content_type == "json":
        try:
            json.loads(text)
        except Exception as e:
            issues.append(f"syntax:json_{type(e).__name__}_{str(e).split('\n')[0][:60]}")
    return issues


# ── Classification ──

def classify_by_first_line(text: str) -> str:
    first = text.split("\n")[0] if text else ""
    if text.startswith('"""') or text.startswith("#!/") or "def " in first:
        return "python"
    if text.startswith("{\"") or text.startswith("["):
        return "json"
    if text.startswith("<") or "DOCTYPE" in text:
        return "html"
    if "---" in first or "title:" in first:
        return "yaml"
    return "text"


def subcategory(text: str) -> str:
    ct = classify_by_first_line(text)
    fl = text.split("\n")[0] if text else ""
    if ct == "python":
        if "pytest" in fl or "import pytest" in text[:200]:
            return "python-test"
        if "def " in fl or "class " in fl:
            return "python-module"
        if text.startswith("#!/"):
            return "python-script"
        return "python-other"
    if ct == "text":
        if text.startswith("# ") or text.startswith("## "):
            return "markdown"
        if "AP " in fl or "— " in fl:
            return "news"
        if "BEGIN" in text[:200]:
            return "pgp"
        if "```" in text[:200]:
            return "code-in-text"
        return "plaintext"
    return ct


# ── Scoring ──

POISON_WEIGHTS = {
    "repetition": 3,
    "truncated": 2,
    "encoding": 2,
    "syntax:python": 3,
    "syntax:yaml": 1,
    "syntax:json": 1,
    "import:subprocess": 2,
    "exec:eval": 3,
    "exec:exec": 3,
    "import:os.system": 2,
    "import:pickle": 2,
    "import:requests": 1,
    "import:socket": 1,
    "dead_code": 1,
    "pattern:infinite_loop": 2,
    "pattern:empty_loop": 1,
    "language:mixed": 1,
}


def poison_score(issues: list[str]) -> int:
    score = 0
    for issue in issues:
        for key, weight in POISON_WEIGHTS.items():
            if key in issue:
                score += weight
                break
    return score


def is_poisoned(score: int) -> bool:
    return score >= 3


def main():
    samples = load_samples()
    print(f"Loaded {len(samples)} samples\n")

    labeled = []
    poisoned_count = 0
    clean_count = 0
    score_dist = Counter()

    for s in samples:
        text = s["text"]
        ct = s.get("content_type", classify_by_first_line(text))
        cat = subcategory(text)

        # Collect all issues
        issues = []
        issues.extend(detect_repetition(text))
        issues.extend(detect_truncation(text))
        issues.extend(detect_encoding_issues(text))
        issues.extend(detect_suspicious_imports(text))
        issues.extend(detect_dead_code(text))
        issues.extend(detect_infinite_loops(text))
        issues.extend(detect_mixed_languages(text))
        issues.extend(detect_broken_syntax(text, ct))

        score = poison_score(issues)
        poisoned = is_poisoned(score)

        if poisoned:
            poisoned_count += 1
        else:
            clean_count += 1
        score_dist[score] += 1

        # Build labeled record
        record = {
            "index": s["index"],
            "content_type": ct,
            "category": cat,
            "size": s["size"],
            "lines": s["lines"],
            "poisoned": poisoned,
            "poison_score": score,
            "issues": issues,
            "first_line": s["first_line"],
            "text": text,
        }
        labeled.append(record)

    # Write dataset
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        for rec in labeled:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Summary
    print(f"Total: {len(labeled)}")
    print(f"Poisoned: {poisoned_count} ({100*poisoned_count//len(labeled)}%)")
    print(f"Clean:   {clean_count} ({100*clean_count//len(labeled)}%)")
    print(f"\nScore distribution:")
    for score, count in sorted(score_dist.items()):
        print(f"  {score}: {count}")
    print(f"\nSaved to {OUT_PATH}")

    # Show poisoned breakdown by category
    print("\nPoisoned by category:")
    cat_counts = Counter()
    for rec in labeled:
        if rec["poisoned"]:
            cat_counts[rec["category"]] += 1
    for cat, count in cat_counts.most_common():
        print(f"  {cat}: {count}")

    # Show most common issues
    print("\nTop issues among poisoned:")
    issue_counts = Counter()
    for rec in labeled:
        if rec["poisoned"]:
            for issue in rec["issues"]:
                issue_counts[issue] += 1
    for issue, count in issue_counts.most_common(15):
        print(f"  {issue}: {count}")


if __name__ == "__main__":
    main()
