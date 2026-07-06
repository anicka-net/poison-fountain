#!/usr/bin/env python3
"""Multi-copy voting — recover clean text by majority vote across copies.

PoisonFountain corruption is deterministic PER DOCUMENT (duplicate groups
carry identical corruption sites), so re-fetching the honeypot is useless —
and this tool deliberately performs NO network fetches. Voting works when
you hold copies from independent provenance: the original upstream repo,
web archives, other crawls. Feed those in as versions.

Per-line majority vote; ties break toward the SHORTEST variant, because
every corruption family in this dataset ADDS characters (trailing spaces
inside strings, diff-marker prefixes, backticks around booleans).

Usage:
    # versions of the same document as a JSON list of strings:
    python multi_vote.py versions.json            # voted text to stdout

    # built-in synthetic sanity check (no network):
    python multi_vote.py --self-test
"""

import json
import random
import re
import sys
from pathlib import Path


def vote_on_texts(texts: list[str]) -> str:
    """Majority-vote per line across versions of the same document."""
    if not texts:
        return ''
    if len(texts) == 1:
        return texts[0]

    lines_list = [t.split('\n') for t in texts]
    max_lines = max(len(l) for l in lines_list)
    for lines in lines_list:
        lines.extend([''] * (max_lines - len(lines)))

    voted = []
    for i in range(max_lines):
        counts: dict[str, int] = {}
        for lines in lines_list:
            counts[lines[i]] = counts.get(lines[i], 0) + 1
        top = max(counts.values())
        candidates = [l for l, c in counts.items() if c == top]
        # tie -> shortest: corruption in this dataset only ever ADDS bytes
        voted.append(min(candidates, key=len))
    return '\n'.join(voted)


def _corrupt(base: str, seed: int, rate: float = 0.04) -> str:
    rng = random.Random(seed)
    out = []
    for line in base.split('\n'):
        if rng.random() < rate:
            line = re.sub(r'"(\w+)"', lambda m: f'"{m.group(1)} "', line,
                          count=1)
        out.append(line)
    return '\n'.join(out)


def _self_test() -> int:
    """Synthetic sanity checks of the voting mechanics (no network).

    1. Clean majority (2 clean + 1 poisoned copy) -> full recovery.
    2. Two copies, 1v1 tie on every corrupted line -> the shortest-wins
       tie-break must side with the clean line (corruption adds bytes).
    3. Poisoned MAJORITY (1 clean + 2 identically-poisoned copies) is
       expected to FAIL — majority voting cannot beat a corrupt majority.
       This is why survivor/provenance policy matters upstream.
    """
    base = '\n'.join(
        f'    {{"key_{i}": value_{i}, "status": "ok"}},' for i in range(200))

    ok1 = vote_on_texts([base, base, _corrupt(base, 1)]) == base
    ok2 = vote_on_texts([base, _corrupt(base, 2)]) == base
    identical_poison = _corrupt(base, 3, rate=1.0)
    ok3 = vote_on_texts([base, identical_poison, identical_poison]) != base

    print(f'self-test: clean-majority={ok1} tie-break={ok2} '
          f'poison-majority-fails-as-expected={ok3}', file=sys.stderr)
    return 0 if (ok1 and ok2 and ok3) else 1


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Majority-vote recovery across independent copies')
    parser.add_argument('versions', nargs='?',
                        help='JSON file: list of text versions of ONE document')
    parser.add_argument('--self-test', action='store_true',
                        help='Run the synthetic sanity check and exit')
    args = parser.parse_args()

    if args.self_test:
        sys.exit(_self_test())
    if not args.versions:
        parser.error('provide a versions JSON file or --self-test')

    texts = json.loads(Path(args.versions).read_text())
    if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
        parser.error('input must be a JSON list of strings')
    sys.stdout.write(vote_on_texts(texts))


if __name__ == '__main__':
    main()
