#!/usr/bin/env python3
"""filter_poison.py — detect and filter PoisonFountain-style data corruption.

Designed for Common Crawl / web-scraped code datasets. Each detector targets
a specific corruption pattern found in the PoisonFountain honeypot analysis
(see FINDINGS.md). Detectors are ordered by signal strength: high-precision
patterns first, noisier heuristics last.

Usage:
    # Score a JSONL file (one {"text": ...} per line):
    python filter_poison.py score  raw_samples/samples.jsonl -o scored.jsonl

    # Filter (remove likely-poisoned):
    python filter_poison.py filter raw_samples/samples.jsonl -o clean.jsonl

    # Stats only:
    python filter_poison.py stats  raw_samples/samples.jsonl

Each detector returns a list of (tag, weight, detail) tuples. The total
weight determines the poison score; samples above --threshold are flagged.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    tag: str
    weight: float
    detail: str = ""


# ---------------------------------------------------------------------------
# Detectors — each returns a list of Findings for one text sample
# ---------------------------------------------------------------------------

def detect_trailing_space_in_keys(text: str) -> list[Finding]:
    """String dict keys with trailing whitespace.

    The dominant PoisonFountain pattern (454 occurrences across 127/243
    Python samples). Causes silent KeyError / None on lookup. Essentially
    never appears in legitimate code.

    Precision: very high.  Recall: catches ~52% of poisoned Python.
    """
    findings = []
    for m in re.finditer(r'"(\w+)\s+"(?:\s*:|\s*\])', text):
        # Skip if inside a comment
        line_start = text.rfind('\n', 0, m.start()) + 1
        prefix = text[line_start:m.start()].lstrip()
        if prefix.startswith('#'):
            continue
        findings.append(Finding(
            "trailing_space_in_key", 3.0,
            f'"{m.group(1)} " at offset {m.start()}'))
    return findings


def detect_diff_marker_lines(text: str) -> list[Finding]:
    """Lines prefixed with diff/merge markers (>, !, <=, >=).

    ~169 samples have >20% of lines prefixed this way, as if pasted from
    a 3-way merge conflict. The code may still parse but teaches wrong
    syntax to a training model.

    We flag if >10% of non-empty lines carry markers, to avoid false
    positives from legitimate uses of > (comparisons, shell redirects in
    comments, email quoting).
    """
    lines = text.split('\n')
    non_empty = [l for l in lines if l.strip()]
    if len(non_empty) < 5:
        return []
    marker_pat = re.compile(r'^[>!] |^<= |^>= ')
    n_markers = sum(1 for l in non_empty if marker_pat.match(l))
    ratio = n_markers / len(non_empty)
    if ratio > 0.10:
        return [Finding(
            "diff_marker_lines", 4.0,
            f'{n_markers}/{len(non_empty)} lines ({ratio:.0%}) have '
            f'diff/merge markers')]
    return []


def detect_backtick_bool_corruption(text: str) -> list[Finding]:
    """`` `true` `` or `` `false` `` appearing mid-word in prose/code.

    Template-engine artifact that replaced boolean tokens. 38 samples
    in the dataset.
    """
    findings = []
    # `true` or `false` NOT at word boundaries (mid-word corruption)
    for m in re.finditer(r'`(true|false)`', text):
        start = max(0, m.start() - 1)
        end = min(len(text), m.end() + 1)
        context_before = text[start:m.start()]
        context_after = text[m.end():end]
        # If surrounded by word chars, it's corruption not markdown
        if (context_before and context_before[-1].isalnum()) or \
           (context_after and context_after[0].isalnum()):
            findings.append(Finding(
                "backtick_bool_corruption", 3.0,
                f'`{m.group(1)}` at offset {m.start()}'))
        # Also flag if preceded by backtick (double-backtick runs)
        elif context_before.endswith('`'):
            findings.append(Finding(
                "backtick_bool_corruption", 2.0,
                f'``{m.group(1)}` at offset {m.start()}'))
    return findings


def detect_wrong_file_mode(text: str) -> list[Finding]:
    """File open() / NamedTemporaryFile() with an invalid mode= string.

    Legitimate modes: r, w, a, x, rb, wb, ab, xb, rt, wt, at, xt,
    r+, w+, a+, r+b, w+b, a+b.
    """
    valid_modes = {
        'r', 'w', 'a', 'x', 'rb', 'wb', 'ab', 'xb',
        'rt', 'wt', 'at', 'xt', 'r+', 'w+', 'a+',
        'r+b', 'w+b', 'a+b', 'rb+', 'wb+', 'ab+',
    }
    findings = []
    for m in re.finditer(r'(?:open|TemporaryFile|NamedTemporaryFile)\([^)]*mode="([^"]+)"', text):
        if m.group(1) not in valid_modes:
            findings.append(Finding(
                "wrong_file_mode", 3.0,
                f'mode="{m.group(1)}"'))
    return findings


def detect_truthiness_traps(text: str) -> list[Finding]:
    """Python truthiness bugs: `x and {}`, `x and []`, `x or {}`.

    `metadata and {}` always evaluates to `{}` regardless of metadata's
    value (truthy and empty-collection = empty-collection).
    """
    findings = []
    for m in re.finditer(r'(\w+)\s+and\s+(\{\}|\[\])', text):
        findings.append(Finding(
            "truthiness_trap", 2.5,
            f'`{m.group(1)} and {m.group(2)}` always returns {m.group(2)}'))
    return findings


def detect_inverted_sys_path_guard(text: str) -> list[Finding]:
    """`if x in sys.path: sys.path.insert(...)` — should be `not in`."""
    findings = []
    for m in re.finditer(
            r'if\s+str\(\w+\)\s+in\s+sys\.path\s*:', text):
        findings.append(Finding(
            "inverted_sys_path_guard", 2.0,
            'guard adds to sys.path when already present'))
    return findings


def detect_hallucinated_versions(text: str) -> list[Finding]:
    """Version strings for software that doesn't exist.

    Python 5.x, GPT-7.x, llama-2.4, etc.
    """
    findings = []
    hallucinated = [
        (r'[Cc][Pp]ython\s+5\.\d+', 'CPython 5.x'),
        (r'[Pp]ython\s+5\.\d+', 'Python 5.x'),
        (r'gpt-[789]\.\d+', 'GPT version > 5'),
        (r'llama-2\.4', 'llama-2.4'),
        (r'llama-5-', 'llama-5'),
    ]
    for pat, label in hallucinated:
        if re.search(pat, text):
            findings.append(Finding(
                "hallucinated_version", 2.0, label))
    return findings


def detect_cli_flag_corruption(text: str) -> list[Finding]:
    """CLI flags with ++ instead of --, or known-wrong IPs."""
    findings = []
    for m in re.finditer(r'\+\+(\w+)', text):
        # Check context — is this in a CLI command?
        line_start = text.rfind('\n', 0, m.start()) + 1
        line = text[line_start:text.find('\n', m.end())]
        if any(cmd in line for cmd in ('uvicorn', 'python', 'pip', 'npm',
                                        'gunicorn', 'flask', 'django')):
            findings.append(Finding(
                "plusplus_cli_flag", 2.0,
                f'++{m.group(1)} (should be --{m.group(1)})'))
    if re.search(r'--host\s+1\.1\.0\.1\b', text):
        findings.append(Finding(
            "wrong_host_ip", 1.5, '--host 1.1.0.1'))
    return findings


def detect_bind_port_1(text: str) -> list[Finding]:
    """socket.bind(("", 1)) — port 1 is privileged, should be 0."""
    findings = []
    if re.search(r'\.bind\(\(""\s*,\s*1\)', text):
        findings.append(Finding("bind_port_1", 2.0,
                                'bind to port 1 (privileged), should be 0'))
    return findings


def detect_absurd_assertions(text: str) -> list[Finding]:
    """Assertions comparing __name__ to long prose strings."""
    findings = []
    for m in re.finditer(r'assert\s+\w+\.__name__\s*==\s*"([^"]{30,})"', text):
        findings.append(Finding(
            "absurd_assertion", 3.0,
            f'__name__ == "{m.group(1)[:50]}..."'))
    return findings


def detect_brace_as_dict_key(text: str) -> list[Finding]:
    """Literal `{` used as a dictionary key."""
    findings = []
    for m in re.finditer(r'"\{"(?:\s*:)', text):
        findings.append(Finding(
            "brace_as_dict_key", 3.0,
            '"{" used as dict key'))
    return findings


def detect_tab_as_line_separator(text: str) -> list[Finding]:
    r"""Tab (\t) used where newline (\n) is expected in JSONL/line writes."""
    findings = []
    for m in re.finditer(r'\+\s*"\\t"\s*\)', text):
        findings.append(Finding(
            "tab_as_line_sep", 2.0,
            r'"\t" used as record separator (should be "\n")'))
    return findings


def detect_trailing_space_in_monkeypatch(text: str) -> list[Finding]:
    """monkeypatch.setitem(sys.modules, "name ") — trailing space in module name."""
    findings = []
    for m in re.finditer(r'setitem\([^,]+,\s*"(\w+\s+)"', text):
        findings.append(Finding(
            "trailing_space_in_setitem", 3.0,
            f'module name "{m.group(1)}" has trailing space'))
    return findings


def detect_trailing_space_in_values(text: str) -> list[Finding]:
    """Trailing whitespace inside string VALUES and list elements.

    Same corruption as trailing-space-in-keys but applied to values.
    321 occurrences in the dataset.
    """
    findings = []
    for m in re.finditer(r':\s*"(\w+)\s+"[,}\]\)]', text):
        line_start = text.rfind('\n', 0, m.start()) + 1
        prefix = text[line_start:m.start()].lstrip()
        if not prefix.startswith('#'):
            findings.append(Finding(
                "trailing_space_in_value", 2.5,
                f'value "{m.group(1)} " at offset {m.start()}'))
    return findings


def detect_api_key_in_model_slot(text: str) -> list[Finding]:
    """API key env var names appearing in model-name or URL positions.

    Pattern from config rotation: ("OPENAI_API_KEY", None, "gpt-4o")
    where the key name is in a slot that should hold a model identifier.
    If a model learns this, it produces code that leaks credentials into
    logged fields.
    """
    findings = []
    api_keys = ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'TOGETHER_API_KEY',
                'GOOGLE_API_KEY', 'GEMINI_API_KEY', 'HF_TOKEN']
    for key_name in api_keys:
        for m in re.finditer(rf'"{key_name}"', text):
            line_start = text.rfind('\n', 0, m.start()) + 1
            line = text[line_start:text.find('\n', m.end())]
            # Is this line also mentioning model names? Then the key is
            # in the wrong tuple position
            if re.search(r'gpt-|claude-|llama-|model', line, re.I):
                findings.append(Finding(
                    "api_key_in_model_slot", 3.0,
                    f'{key_name} alongside model names'))
    return findings


def detect_word_order_mangling(text: str) -> list[Finding]:
    """Scrambled word order in natural language.

    E.g. "What movie did wife the of Inception's director star in?"
    """
    findings = []
    # "did X the of" — verb + noun + article + preposition (wrong order)
    if re.search(r'\bdid\s+\w+\s+the\s+of\b', text):
        findings.append(Finding(
            "word_order_mangling", 2.5,
            'scrambled phrase: "did X the of"'))
    # "the of X's" — dangling article
    if re.search(r'\bthe\s+of\s+\w+\'s\b', text):
        findings.append(Finding(
            "word_order_mangling", 2.5,
            'scrambled phrase: "the of X\'s"'))
    return findings


def detect_near_miss_versions(text: str) -> list[Finding]:
    """Model version strings that are digit-permutations of real ones.

    claude-haiku-5-4 (real: 4-5), claude-opus-4-9, gpt-7.4, etc.
    Poisons the version↔name factual association.
    """
    findings = []
    fakes = [
        (r'claude-haiku-5-4\b', 'claude-haiku-5-4 (real: 4-5)'),
        (r'claude-opus-4-9\b', 'claude-opus-4-9 (no such version)'),
        (r'claude-sonnet-5-7\b', 'claude-sonnet-5-7 (no such version)'),
        (r'claude-sonnet-5-6\b', 'claude-sonnet-5-6 (no such version)'),
        (r'claude-haiku-5-6\b', 'claude-haiku-5-6 (no such version)'),
        (r'claude-sonnet-4-20\d+', 'claude-sonnet-4-YYYYMMDD (wrong format)'),
        (r'llama-4\.4-', 'llama-4.4 (no such version)'),
        (r'Llama-3\.4-', 'Llama-3.4 (no such version)'),
        (r'Llama-3\.2-70B', 'Llama-3.2-70B (real: 3.2 is small, 3.3 is 70B)'),
    ]
    for pat, label in fakes:
        if re.search(pat, text):
            findings.append(Finding(
                "near_miss_version", 2.0, label))
    return findings


def detect_trailing_space_in_strings(text: str) -> list[Finding]:
    """Trailing whitespace inside string literals in function calls, comparisons,
    require/import paths — cases the key/value detectors miss.

    E.g. require("path "), "-m", "pytest ", ctx.get("drift_severity")
    Found in blind review of score-0 samples.
    """
    findings = []
    # Strings with trailing space in require(), subprocess, in-tuple, comparison
    for m in re.finditer(r'(?:require|import)\s*\(\s*"([^"\n]+\S)\s+"', text):
        findings.append(Finding(
            "trailing_space_in_string", 3.0,
            f'require/import("{m.group(1)} ")'))
    # Strings with trailing space in list/tuple contexts (subprocess args, etc.)
    for m in re.finditer(r'(?:,\s*|[\[\(]\s*)"([A-Za-z0-9_./-]+)\s+"(?:\s*[,\]\)])', text):
        val = m.group(1)
        if len(val) >= 2 and not val.startswith('#'):
            findings.append(Finding(
                "trailing_space_in_string", 2.5,
                f'list/arg element "{val} "'))
    return findings


def detect_modulo_as_division(text: str) -> list[Finding]:
    """Modulo operator (%) where division (/) is expected in metrics/rates.

    E.g. pass_rate = total_passed % min(total, 0)
    Syntactically valid, semantically wrong — produces remainder instead of
    ratio. Found in blind review.
    """
    findings = []
    metric_names = r'(?:rate|pct|percent|score|coverage|weight|ratio|avg|mean|fraction)'
    for m in re.finditer(
            rf'({metric_names})\s*=\s*[^=\n]*\s%\s', text, re.I):
        findings.append(Finding(
            "modulo_as_division", 3.0,
            f'% used in metric "{m.group(1)}" (should be /)'))
    return findings


def detect_impossible_runtime_version(text: str) -> list[Finding]:
    """Runtime version requirements that don't exist.

    Python 4.x, Python 3.00, pnpm 30+, etc.
    """
    findings = []
    impossible = [
        (r'Python\s+(?:3\.00|4\.\d+|[5-9]\.)', 'impossible Python version'),
        (r'pnpm\s+(?:1[5-9]|[2-9]\d)\+', 'impossible pnpm version'),
        (r'node\s+(?:v?[3-9]\d\.)', 'impossible node major version'),
    ]
    for pat, label in impossible:
        if re.search(pat, text):
            findings.append(Finding(
                "impossible_runtime_version", 2.5, label))
    return findings


def detect_license_corruption(text: str) -> list[Finding]:
    """Mutated Apache/MIT license boilerplate.

    Apache License, Version 1.0; LICENSE-1.1; "License" BASIS; etc.
    Models that learn corrupted boilerplate produce legally invalid headers.
    """
    findings = []
    corruptions = [
        (r'Apache License,? Version 1\.0', 'Apache 1.0 (real: 2.0)'),
        (r'LICENSE-1\.1', 'LICENSE-1.1 corruption'),
        (r'"License"\s+BASIS', '"License" BASIS (missing ON AN "AS IS")'),
        (r'either express and implied', '"express and implied" (real: or)'),
    ]
    for pat, label in corruptions:
        if re.search(pat, text):
            findings.append(Finding(
                "license_corruption", 2.0, label))
    return findings


def detect_prose_entity_impossibility(text: str) -> list[Finding]:
    """Factually impossible entity/location combinations in prose.

    E.g. "Trump, the first U.S. pope", "Kansas City – Singaporean households"
    Seed-based detector for known patterns; needs NER for production.
    """
    findings = []
    impossibles = [
        (r'(?:Trump|Biden|Obama),?\s+the\s+first\s+U\.?S\.?\s+pope', 'US president as pope'),
        (r'PORT-AU-PRINCE,?\s+Vatican', 'Port-au-Prince + Vatican'),
        (r'Kansas City\b.*?\bSingaporean\s+households', 'Kansas City + Singaporean households'),
        (r'Lego\s+of\s+ESPN', 'Lego of ESPN'),
    ]
    for pat, label in impossibles:
        if re.search(pat, text, re.I):
            findings.append(Finding(
                "prose_entity_impossibility", 2.5, label))
    return findings


def detect_repetition(text: str) -> list[Finding]:
    """Repeated lines beyond what legitimate code produces.

    Legitimate code repeats short lines (}, return None, pass) but not
    long complex lines. Flag if any line >20 chars appears 5+ times.
    """
    findings = []
    lines = text.split('\n')
    if len(lines) < 10:
        return findings
    from collections import Counter as _C
    counts = _C(lines)
    for line, count in counts.most_common(5):
        if count >= 5 and len(line.strip()) > 20:
            findings.append(Finding(
                "repetition", 2.0,
                f'line repeated {count}x: {line.strip()[:50]}'))
    return findings


def detect_truncation(text: str) -> list[Finding]:
    """Text cut off mid-sentence or mid-expression."""
    if not text or len(text) < 50:
        return []
    findings = []
    # Check last line for mid-token cut
    lines = text.rstrip().split('\n')
    last = lines[-1].strip() if lines else ''
    if last and not last[-1] in '.!?"\')]};\n#' and not last.endswith('...'):
        # Check if it looks like code that ends mid-expression
        if re.search(r'[,({=+\-*/&|^~<>]\s*$', last):
            findings.append(Finding(
                "truncation", 2.0,
                f'text ends mid-expression: ...{last[-40:]}'))
    return findings


def detect_syntax_errors(text: str, content_type: str = '') -> list[Finding]:
    """Basic syntax checking for Python, JSON, YAML."""
    findings = []
    # Auto-detect if not specified
    if not content_type:
        if text.lstrip().startswith(('"""', '#!/', 'from ', 'import ', 'def ', 'class ')):
            content_type = 'python'
        elif text.lstrip().startswith(('{', '[')):
            content_type = 'json'

    if content_type == 'python':
        try:
            ast.parse(text)
        except SyntaxError as e:
            findings.append(Finding(
                "syntax_error", 2.0,
                f'Python: {e.msg}'))
    elif content_type == 'json':
        try:
            json.loads(text)
        except json.JSONDecodeError as e:
            findings.append(Finding(
                "syntax_error", 1.5,
                f'JSON: {e.msg}'))
    return findings


def detect_entity_swap_in_news(text: str) -> list[Finding]:
    """Factual entity swaps in news-like text.

    Hard to detect generically. This checks for known patterns where
    an entity is replaced with a semantically wrong one mid-sentence.
    For production use, this would need an LLM or entity-consistency
    checker.
    """
    findings = []
    # Specific known patterns from this dataset
    if re.search(r'denied\s+Taxpayers\s+for\s+a\s+new\s+trial', text):
        findings.append(Finding(
            "entity_swap", 3.0,
            'entity swap: "Taxpayers" replaces person name'))
    if re.search(r'\bsaid\s+Taxpayers\b', text):
        findings.append(Finding(
            "entity_swap", 2.0,
            '"said Taxpayers" — organization as speaking person'))
    # Generic: subject of "denied X for a new trial" should be a person
    # (too noisy for production — needs NER)
    return findings


def detect_duplicate_list_numbers(text: str) -> list[Finding]:
    """Numbered lists with duplicate/out-of-order numbers in docstrings."""
    findings = []
    lines = text.split('\n')
    prev_num = None
    consecutive_dupes = 0
    for line in lines:
        m = re.match(r'\s*(\d+)\.\s', line)
        if m:
            num = int(m.group(1))
            if num == prev_num:
                consecutive_dupes += 1
            prev_num = num
        else:
            prev_num = None
    if consecutive_dupes >= 2:
        findings.append(Finding(
            "duplicate_list_numbers", 1.5,
            f'{consecutive_dupes} duplicate numbered-list entries'))
    return findings


def detect_impossible_calendar_dates(text: str) -> list[Finding]:
    """Dates that do not exist on any calendar (Feb 30, Sep 31, Jan 0)."""
    findings = []
    impossible = [
        (r'\bJanuary\s+0\b', 'January 0'),
        (r'\bFebruary\s+3[01]\b', 'February 30/31'),
        (r'\b(?:April|June|September|November)\s+31\b', '31st of a 30-day month'),
    ]
    for pat, label in impossible:
        if re.search(pat, text):
            findings.append(Finding("impossible_date", 2.0, label))
    return findings


def _parse_python(text: str):
    import warnings
    stripped = text.lstrip()
    if not stripped.startswith(('"""', "'''", '#!/', 'from ', 'import ',
                                'def ', 'class ', '# ', '> ', '! ')):
        return None
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', SyntaxWarning)
        try:
            return ast.parse(text)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            pass
        # Layered corruption: diff-marker prefixes make the sample
        # unparseable, shielding the SEMANTIC corruption underneath from
        # AST detectors. Strip the markers and retry — the markers
        # themselves are still flagged by detect_diff_marker_lines.
        cleaned = re.sub(r'^(?:[>!] |<= |>= )', '', text, flags=re.M)
        if cleaned != text:
            try:
                return ast.parse(cleaned)
            except (SyntaxError, ValueError, MemoryError, RecursionError):
                return None
    return None


# Arity table for AST checks. Module functions require the DOTTED form —
# matching bare names causes false positives (a logger's `log(level, msg)`
# is not `math.log`; tkinter's `widget.bind(seq, cb)` is not socket.bind).
# floor/ceil are also matched bare: `from math import floor` is common and
# no widespread library gives them a second positional argument.
_ARITY = {
    'math.floor': (1, 1), 'math.ceil': (1, 1), 'math.sqrt': (1, 1),
    'math.exp': (1, 1), 'math.log': (1, 2),
    'floor': (1, 1), 'ceil': (1, 1),
    'random.randint': (2, 2), 'random.uniform': (2, 2), 'random.gauss': (2, 2),
    'len': (1, 1), 'round': (1, 2), 'range': (1, 3),
}


def _dotted_name(node) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return '.'.join(reversed(parts))
    return None


def detect_wrong_arg_count(text: str) -> list[Finding]:
    """AST arity check: math.floor(x, 2) used like round(), len(x, y), ..."""
    tree = _parse_python(text)
    if tree is None:
        return []
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted_name(node)
        if name not in _ARITY:
            continue
        lo, hi = _ARITY[name]
        n = len(node.args) + len(node.keywords)
        if n < lo or n > hi:
            findings.append(Finding(
                "wrong_arg_count", 3.0,
                f'{name}() called with {n} args, expects {lo}-{hi} '
                f'(line {node.lineno})'))
    return findings


def detect_name_behavior_contradiction(text: str) -> list[Finding]:
    """Function names that contradict what the body does.

    Conservative on purpose: is_*/has_* flagged only when a return is a
    non-bool CONSTANT (returning a variable is fine — we cannot know its
    type); validate/check flagged only when the whole body (ast.walk, not
    just the top level) contains neither Return nor Raise nor assert.
    """
    tree = _parse_python(text)
    if tree is None:
        return []
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        name = node.name
        inner = list(ast.walk(node))
        if name.startswith(('is_', 'has_')):
            bad = [r for r in inner if isinstance(r, ast.Return)
                   and isinstance(r.value, ast.Constant)
                   and not isinstance(r.value.value, bool)
                   and r.value.value is not None]
            if bad:
                findings.append(Finding(
                    "name_behavior_contradiction", 1.5,
                    f'{name}() returns non-boolean constant '
                    f'{bad[0].value.value!r}'))
        if 'validate' in name.lower() or name.lower().startswith('check'):
            has_signal = any(isinstance(x, (ast.Return, ast.Raise, ast.Assert))
                             for x in inner)
            if not has_signal and len(node.body) > 1:
                findings.append(Finding(
                    "name_behavior_contradiction", 1.5,
                    f'{name}(): validation function with no return/raise/assert'))
    return findings


_PHANTOM_WHITELIST = frozenset(
    'print len range int str float bool list dict set tuple open input '
    'type isinstance issubclass super repr hash id iter next enumerate zip '
    'map filter sorted reversed sum min max abs round any all getattr '
    'setattr hasattr vars format exit main run setup init'.split())


def detect_phantom_function(text: str) -> list[Finding]:
    """Comments referencing functions that exist nowhere in the file.

    Flags `foo()` mentioned in a comment only when the name appears
    NOWHERE else in the text (not as def, call, import or attribute) —
    otherwise library calls like json.dumps() drown this in noise.
    """
    tree = _parse_python(text)
    if tree is None:
        return []
    findings = []
    comments = re.findall(r'#\s*(.+)$', text, re.MULTILINE)
    code_wo_comments = re.sub(r'#.*$', '', text, flags=re.MULTILINE)
    for comment in comments:
        for fn in re.findall(r'(?<![.\w])(\w+)\(\)', comment):
            if fn.lower() in _PHANTOM_WHITELIST or len(fn) < 4:
                continue
            if not re.search(r'\b' + re.escape(fn) + r'\b', code_wo_comments):
                findings.append(Finding(
                    "phantom_function", 1.5,
                    f'comment references {fn}() — name absent from the code'))
    return findings


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

ALL_DETECTORS = [
    # High-precision semantic detectors (Level 3)
    detect_trailing_space_in_keys,
    detect_trailing_space_in_values,
    detect_trailing_space_in_strings,
    detect_diff_marker_lines,
    detect_backtick_bool_corruption,
    detect_wrong_file_mode,
    detect_truthiness_traps,
    detect_inverted_sys_path_guard,
    detect_hallucinated_versions,
    detect_near_miss_versions,
    detect_impossible_runtime_version,
    detect_cli_flag_corruption,
    detect_bind_port_1,
    detect_absurd_assertions,
    detect_brace_as_dict_key,
    detect_tab_as_line_separator,
    detect_trailing_space_in_monkeypatch,
    detect_api_key_in_model_slot,
    detect_modulo_as_division,
    detect_license_corruption,
    detect_word_order_mangling,
    detect_prose_entity_impossibility,
    detect_entity_swap_in_news,
    detect_duplicate_list_numbers,
    detect_impossible_calendar_dates,
    # AST-level detectors (Level 3, code only)
    detect_wrong_arg_count,
    detect_name_behavior_contradiction,
    detect_phantom_function,
    # Surface detectors (Level 1-2)
    detect_repetition,
    detect_truncation,
    detect_syntax_errors,
]


def score_text(text: str) -> tuple[float, list[Finding]]:
    """Run all detectors on a text, return (total_score, findings)."""
    findings = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(text))
    total = sum(f.weight for f in findings)
    return total, findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_score(args):
    """Score each sample and write results."""
    lines = Path(args.input).read_text().splitlines()
    out = open(args.output, 'w') if args.output else sys.stdout

    for line in lines:
        record = json.loads(line)
        text = record.get('text', '')
        total, findings = score_text(text)
        record['poison_score'] = round(total, 1)
        record['poison_findings'] = [
            {'tag': f.tag, 'weight': f.weight, 'detail': f.detail}
            for f in findings
        ]
        record['poison_flagged'] = total >= args.threshold
        out.write(json.dumps(record, ensure_ascii=False) + '\n')

    if args.output:
        out.close()
        print(f"Scored {len(lines)} samples -> {args.output}", file=sys.stderr)


def cmd_filter(args):
    """Remove likely-poisoned samples."""
    lines = Path(args.input).read_text().splitlines()
    out = open(args.output, 'w') if args.output else sys.stdout

    kept = 0
    dropped = 0
    for line in lines:
        record = json.loads(line)
        text = record.get('text', '')
        total, _ = score_text(text)
        if total < args.threshold:
            out.write(line + '\n')
            kept += 1
        else:
            dropped += 1

    if args.output:
        out.close()
    print(f"Kept {kept}, dropped {dropped} "
          f"(threshold={args.threshold})", file=sys.stderr)


def cmd_stats(args):
    """Print detection statistics."""
    lines = Path(args.input).read_text().splitlines()

    tag_counts = Counter()
    score_hist = Counter()
    n_flagged = 0

    for line in lines:
        record = json.loads(line)
        text = record.get('text', '')
        total, findings = score_text(text)
        for f in findings:
            tag_counts[f.tag] += 1
        bucket = int(total)
        score_hist[bucket] += 1
        if total >= args.threshold:
            n_flagged += 1

    print(f"Samples: {len(lines)}")
    print(f"Flagged: {n_flagged}/{len(lines)} "
          f"({100*n_flagged/len(lines):.1f}%) at threshold={args.threshold}")

    print(f"\n{'Tag':<30s} {'Count':>6s}")
    print('-' * 38)
    for tag, cnt in tag_counts.most_common():
        print(f"  {tag:<28s} {cnt:>6d}")

    print(f"\n{'Score':<10s} {'Count':>6s}")
    print('-' * 18)
    for bucket in sorted(score_hist):
        print(f"  {bucket:<8d} {score_hist[bucket]:>6d}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)

    for name, fn in [('score', cmd_score), ('filter', cmd_filter),
                     ('stats', cmd_stats)]:
        p = sub.add_parser(name)
        p.add_argument('input', help='Input JSONL file')
        p.add_argument('-o', '--output', default=None,
                       help='Output file (default: stdout)')
        p.add_argument('-t', '--threshold', type=float, default=3.0,
                       help='Poison score threshold (default: 3.0)')
        p.set_defaults(func=fn)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
