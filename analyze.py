#!/usr/bin/env python3
"""Analyze PoisonFountain samples — categorize, check code correctness, find breakage."""

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml  # needs: pip install pyyaml

SAMPLES_PATH = Path(__file__).resolve().parent / "raw_samples" / "samples.jsonl"


def load_samples():
    lines = Path(SAMPLES_PATH).read_text().splitlines()
    samples = [json.loads(line) for line in lines]
    return samples


# ── Categorization ──

def categorize(s: dict) -> str:
    ct = s.get("content_type", "")
    text = s.get("text", "")
    fl = s.get("first_line", "")

    # Python sub-types
    if ct == "python":
        if "pytest" in fl or "import pytest" in text[:200]:
            return "python-test"
        if "def " in fl or "class " in fl:
            return "python-module"
        if text.startswith("#!/"):
            return "python-script"
        return "python-other"

    # Text sub-types
    if ct == "text":
        if text.startswith("# ") or text.startswith("## "):
            return "markdown"
        if text.startswith("From ") or "Subject:" in text[:200]:
            return "email"
        if "BEGIN" in text[:200] or "END" in text[:200]:
            return "pgp"
        if "AP " in fl or "— " in fl:
            return "news"
        if "```" in text[:200]:
            return "code-in-text"
        # Check for structured data
        if re.match(r"^[A-Z][a-z]+:", fl):
            return "structured-text"
        return "plaintext"

    if ct == "yaml":
        return "yaml"

    if ct == "json":
        return "json"

    if ct == "html":
        return "html"

    return "other"


# ── Code analysis ──

def analyze_python(text: str) -> dict:
    """Check Python code for syntax correctness and common issues."""
    result = {"valid": False, "issues": []}

    # Syntax check
    try:
        ast.parse(text)
        result["valid"] = True
    except SyntaxError as e:
        result["issues"].append(f"syntax: {e}")

    # Common patterns of poisoning
    # Check for suspicious imports
    bad_imports = ["os.system", "subprocess", "eval(", "exec(", "pickle.load", "requests.get("]
    for pat in bad_imports:
        if pat in text:
            result["issues"].append(f"suspicious: contains '{pat}'")

    # Check for infinite loops or recursion
    if re.search(r"while True:|while 1:", text):
        result["issues"].append("pattern: infinite while loop")

    # Check for commented-out code blocks that look like real code
    comment_blocks = re.findall(r"# .*def |# .*class |# .*for |# .*if ", text)
    if comment_blocks:
        result["issues"].append(f"pattern: {len(comment_blocks)} commented code statements")

    # Check for encoding issues
    if "\x00" in text:
        result["issues"].append("encoding: null bytes present")

    # Check for truncated code
    lines = text.split("\n")
    if not text.endswith("\n") and len(lines) > 0 and not lines[-1].strip():
        result["issues"].append("structure: might be truncated")

    return result


def analyze_yaml(text: str) -> dict:
    result = {"valid": False, "issues": []}
    try:
        yaml.safe_load(text)
        result["valid"] = True
    except Exception as e:
        result["issues"].append(f"syntax: {e}")
    return result


def analyze_json(text: str) -> dict:
    result = {"valid": False, "issues": []}
    try:
        json.loads(text)
        result["valid"] = True
    except Exception as e:
        result["issues"].append(f"syntax: {e}")
    return result


def analyze_text(text: str) -> dict:
    """Check text for issues — truncation, encoding, repetition, contamination."""
    result = {"issues": []}

    # Truncation
    if not text.endswith("\n") and text[-1] not in ".!?\"')\n":
        result["issues"].append("truncated: text does not end with sentence boundary")

    # Encoding issues
    if "\x00" in text:
        result["issues"].append("encoding: null bytes")
    bad_chars = set("\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f")
    if any(c in text for c in bad_chars):
        result["issues"].append("encoding: control characters")

    # Repetition (likely contamination)
    lines = text.split("\n")
    if len(lines) >= 10:
        repeats = Counter(lines).most_common(3)
        for line, count in repeats:
            if count > 1 and len(line) > 20:
                result["issues"].append(f"repetition: line repeated {count}x: {line[:40]}")

    # Mixed languages
    # Simple heuristic: count non-ASCII characters
    non_ascii = sum(1 for c in text if ord(c) > 127)
    total = len(text)
    if total > 0 and non_ascii / total > 0.3:
        result["issues"].append("language: >30% non-ASCII characters")

    return result


# ── Main ──

def main():
    samples = load_samples()
    print(f"Loaded {len(samples)} samples\n")

    # 1. Categorize
    cats = Counter()
    for s in samples:
        cats[categorize(s)] += 1

    print("=== CATEGORIES ===")
    for cat, count in cats.most_common():
        print(f"  {cat}: {count}")
    print()

    # 2. Analyze code samples
    code_samples = [s for s in samples if s["content_type"] == "python"]
    print(f"=== PYTHON ANALYSIS ({len(code_samples)} samples) ===")
    valid = 0
    all_issues: list[str] = []
    for s in code_samples:
        r = analyze_python(s["text"])
        if r["valid"]:
            valid += 1
        for issue in r["issues"]:
            all_issues.append(issue)
    print(f"  Valid syntax: {valid}/{len(code_samples)} ({100*valid//len(code_samples)}%)")
    print(f"  Issues found: {len(all_issues)}")
    if all_issues:
        issue_counts = Counter(all_issues)
        for issue, count in issue_counts.most_common(10):
            print(f"    {issue}: {count}")
    print()

    # 3. Analyze YAML
    yaml_samples = [s for s in samples if s["content_type"] == "yaml"]
    print(f"=== YAML ANALYSIS ({len(yaml_samples)} samples) ===")
    valid_y = 0
    for s in yaml_samples:
        r = analyze_yaml(s["text"])
        if r["valid"]:
            valid_y += 1
    print(f"  Valid: {valid_y}/{len(yaml_samples)}")
    print()

    # 4. Analyze JSON
    json_samples = [s for s in samples if s["content_type"] == "json"]
    print(f"=== JSON ANALYSIS ({len(json_samples)} samples) ===")
    valid_j = 0
    for s in json_samples:
        r = analyze_json(s["text"])
        if r["valid"]:
            valid_j += 1
    print(f"  Valid: {valid_j}/{len(json_samples)}")
    print()

    # 5. Text analysis
    text_samples = [s for s in samples if s["content_type"] == "text"]
    print(f"=== TEXT ANALYSIS ({len(text_samples)} samples) ===")
    text_issues: list[str] = []
    for s in text_samples:
        r = analyze_text(s["text"])
        for issue in r["issues"]:
            text_issues.append(issue)
    print(f"  Samples with issues: {len(set(text_issues))}")
    issue_counts = Counter(text_issues)
    for issue, count in issue_counts.most_common(10):
        print(f"    {issue}: {count}")
    print()

    # 6. Show some interesting broken samples
    print("=== INTERESTING BREAKAGE SAMPLES ===")
    broken = [s for s in code_samples if not analyze_python(s["text"])["valid"]]
    for s in broken[:5]:
        print(f"  Sample {s['index']}: {s['first_line'][:80]}")
        r = analyze_python(s["text"])
        for issue in r["issues"]:
            print(f"    {issue}")
        print()


if __name__ == "__main__":
    main()
