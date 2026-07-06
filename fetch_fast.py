#!/usr/bin/env python3
"""Fetch samples concurrently for speed."""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import requests

URL = "https://rnsaffn.com/poison2/"
TARGET = 1000
OUT_DIR = Path(__file__).resolve().parent / "raw_samples"
BATCH_SIZE = 20  # concurrent requests per batch
BATCH_DELAY = 0.5  # seconds between batches


def fetch_one(idx: int) -> dict | None:
    try:
        r = requests.get(URL, timeout=30)
        r.raise_for_status()
        text = r.text
        first = text.split("\n")[0] if text else ""
        lines = text.count("\n")
        return {
            "index": idx,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "size": len(text),
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
    idx = 0
    lock = threading.Lock()

    while len(samples) < TARGET:
        batch_results = [None] * BATCH_SIZE
        threads = []

        def fetch_and_store(batch_pos: int, global_idx: int):
            s = fetch_one(global_idx)
            with lock:
                if s is None or "error" in s:
                    batch_results[batch_pos] = {"error": True}
                else:
                    batch_results[batch_pos] = s

        for i in range(BATCH_SIZE):
            idx += 1
            t = threading.Thread(target=fetch_and_store, args=(i, idx))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        # Collect results
        for r in batch_results:
            if r is None or r.get("error"):
                errors += 1
            else:
                samples.append(r)

        print(f"  {len(samples)} samples, {errors} errors", flush=True)

        # Write batch
        mode = "w" if len(samples) <= BATCH_SIZE else "a"
        with out_path.open(mode, encoding="utf-8") as f:
            for s in batch_results:
                if s and not s.get("error"):
                    f.write(json.dumps(s, ensure_ascii=False) + "\n")

        import time
        time.sleep(BATCH_DELAY)

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
