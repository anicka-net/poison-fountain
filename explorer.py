#!/usr/bin/env python3
"""Interactive explorer — browse samples by poison type, corruption highlighted.

Usage:
    python explorer.py labeled_dataset.jsonl                 # curses browser
    python explorer.py labeled_dataset.jsonl -t repetition   # filter by tag
    python explorer.py labeled_dataset.jsonl --poisoned-only
    python explorer.py labeled_dataset.jsonl --list-tags
    python explorer.py labeled_dataset.jsonl --dump 42       # plain text, no curses

Keys in the browser: n/j next, p/k previous, g first, G last, q quit.
"""

import json
import sys
from pathlib import Path

FINDING_FIELDS = ('issues', 'poison_findings', 'ast_findings',
                  'prose_findings', 'semantic_findings')


def get_findings(record: dict) -> list[dict]:
    """Collect findings from every known field (they are not exclusive)."""
    out = []
    for f in FINDING_FIELDS:
        out.extend(record.get(f) or [])
    return out


def format_record(record: dict, max_text_lines: int = 30) -> str:
    """Plain-text rendering of one record (for --dump / non-tty use)."""
    findings = get_findings(record)
    flag = 'POISONED' if record.get('poisoned') else 'clean'
    score = record.get('poison_score', record.get('score', 0))
    lines = [
        f"[{record.get('index', '?')}] {flag} score={score} "
        f"{record.get('content_type', '?')}/{record.get('category', '?')} "
        f"{record.get('size', 0)}B",
    ]
    for f in findings:
        lines.append(f"  - {f.get('tag', '?')} (w={f.get('weight', 0)}): "
                     f"{f.get('detail', '')[:100]}")
    lines.append('-' * 60)
    lines.extend((record.get('text') or '').split('\n')[:max_text_lines])
    return '\n'.join(lines)


def browse(samples: list[dict], filter_tag: str | None = None,
           poisoned_only: bool = False):
    import curses

    filtered = []
    for s in samples:
        if poisoned_only and not s.get('poisoned', False):
            continue
        if filter_tag:
            tags = {f.get('tag', '') for f in get_findings(s)}
            if filter_tag not in tags:
                continue
        filtered.append(s)

    if not filtered:
        print("No samples match filter")
        return

    def put(stdscr, y, x, text, attr=0):
        """addstr that never throws on narrow terminals / edge rows."""
        h, w = stdscr.getmaxyx()
        if 0 <= y < h:
            try:
                stdscr.addstr(y, x, text[:max(w - x - 1, 0)], attr)
            except Exception:
                pass

    def run(stdscr):
        curses.curs_set(0)
        current = 0
        n = len(filtered)

        while True:
            stdscr.clear()
            height, _ = stdscr.getmaxyx()
            s = filtered[current]
            findings = get_findings(s)
            # snippets that let us spot a corrupt line (quoted parts of details)
            needles = []
            for f in findings:
                d = f.get('detail', '')
                needles.extend(p for p in d.split('"')[1::2] if len(p) >= 3)

            flag = 'POISONED' if s.get('poisoned') else 'clean'
            put(stdscr, 0, 0,
                f"[{current+1}/{n}] sample {s.get('index', '?')} {flag} "
                f"score={s.get('poison_score', s.get('score', 0))}",
                curses.A_BOLD)

            y = 2
            for line in (s.get('text') or '').split('\n')[:20]:
                if y >= height - 2:
                    break
                hot = any(nd in line for nd in needles)
                put(stdscr, y, 0, line, curses.A_REVERSE if hot else 0)
                y += 1

            y += 1
            if findings and y < height - 1:
                put(stdscr, y, 0, f"Findings ({len(findings)}):", curses.A_BOLD)
                y += 1
                for f in findings:
                    if y >= height - 1:
                        break
                    put(stdscr, y, 2,
                        f"{f.get('tag', '?')} (w={f.get('weight', 0)}): "
                        f"{f.get('detail', '')}")
                    y += 1

            put(stdscr, height - 1, 0,
                'n/j next  p/k prev  g/G first/last  q quit', curses.A_REVERSE)

            key = stdscr.getch()
            if key == ord('q'):
                break
            elif key in (ord('n'), ord('j'), ord('\t'), curses.KEY_RIGHT):
                current = (current + 1) % n
            elif key in (ord('p'), ord('k'), curses.KEY_LEFT):
                current = (current - 1) % n
            elif key == ord('g'):
                current = 0
            elif key == ord('G'):
                current = n - 1

    curses.wrapper(run)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Interactive poison explorer')
    parser.add_argument('input', help='Input JSONL file')
    parser.add_argument('--type', '-t', default=None, help='Filter by tag')
    parser.add_argument('--poisoned-only', '-p', action='store_true')
    parser.add_argument('--list-tags', action='store_true',
                        help='List all tag types and exit')
    parser.add_argument('--dump', type=int, metavar='INDEX', default=None,
                        help='Print one sample as plain text (no curses)')
    args = parser.parse_args()

    samples = [json.loads(line)
               for line in Path(args.input).read_text().splitlines()]

    if args.list_tags:
        tags = sorted({f.get('tag', '') for s in samples
                       for f in get_findings(s)})
        print('\n'.join(tags))
        return

    if args.dump is not None:
        matches = [s for s in samples if s.get('index') == args.dump]
        if not matches:
            sys.exit(f'no sample with index {args.dump}')
        print(format_record(matches[0]))
        return

    browse(samples, filter_tag=args.type, poisoned_only=args.poisoned_only)


if __name__ == '__main__':
    main()
