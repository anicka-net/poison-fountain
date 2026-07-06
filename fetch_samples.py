#!/usr/bin/env python3
"""Fetch ~1000 random samples from PoisonFountain dataset."""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

URL = "https://rnsaffn.com/poison2/"
TARGET = 1000
BATCH = 100  # write every N samples
OUT_DIR = Path(__file__).resolve().parent / "raw_samples"


def fetch_one(idx: int) -> dict | None:
    try:
        r = requests.get(URL, timeout=30)
        r.raise_for_status()
        text = r.text
        first = text.split("\n")[0] if text else ""
        lines = text.count("\n")
        size = len(text)
        return {
            "index": idx,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "size": size,
            "lines": lines,
            "content_type": _classify(text, first),
            "first_line": first[:200],
            "text": text,
        }
    except Exception as e:
        return {"index": idx, "error": str(e)}


def _classify(text: str, first_line: str) -> str:
    if text.startswith('"""') or text.startswith("#!/") or "def " in first_line:
        return "python"
    if text.startswith("{\"") or text.startswith("["):
        return "json"
    if text.startswith("<") or "DOCTYPE" in text:
        return "html"
    if "---" in first_line or "title:" in first_line:
        return "yaml"
    return "text"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "samples.jsonl"
    samples: list[dict] = []
    errors = 0
    consecutive_failures = 0
    idx = 0
    batch_n = 0

    while len(samples) < TARGET:
        idx += 1
        s = fetch_one(idx)
        if s is None or "error" in s:
            errors += 1
            consecutive_failures += 1
            if consecutive_failures >= 5:
                print(f"  Stopping after {consecutive_failures} consecutive failures")
                break
            continue
        consecutive_failures = 0
        samples.append(s)

        if len(samples) % BATCH == 0:
            mode = "w" if batch_n == 0 else "a"
            with out_path.open(mode, encoding="utf-8") as f:
                for s in samples[-BATCH:]:
                    f.write(json.dumps(s, ensure_ascii=False) + "\n")
            batch_n += 1
            print(f"  {len(samples)} samples, {errors} errors", flush=True)

        time.sleep(0.03)

    # Write final batch if not already written
    remaining = len(samples) - batch_n * BATCH
    if remaining > 0:
        mode = "w" if batch_n == 0 else "a"
        with out_path.open(mode, encoding="utf-8") as f:
            for s in samples[-remaining:]:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")

    # Summary
    types = {}
    for s in samples:
        ct = s.get("content_type", "?")
        types[ct] = types.get(ct, 0) + 1

    print(f"\nCollected {len(samples)} samples ({errors} errors)")
    print(f"Saved to {out_path}")
    print(f"\nContent types:")
    for ct, count in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {ct}: {count}")


if __name__ == "__main__":
    main()
