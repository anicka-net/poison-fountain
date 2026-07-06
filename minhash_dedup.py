#!/usr/bin/env python3
"""MinHash dedup analysis — show which samples cluster with clean originals.

Based on FINDINGS.md §K: at ~3.7% trailing-space corruption, 73% of poisoned
samples land in the same MinHash bucket as their clean form. The survivor
policy (keep-first vs rank-by-provenance) determines whether poison or clean
enters your corpus.

Usage:
    python minhash_dedup.py raw_samples/samples.jsonl -o dedup_clusters.json
"""

import hashlib
import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

# ── MinHash parameters ──
SHINGLE_SIZE = 5        # words per shingle
N_HASHES = 128          # signature length
LSH_BANDS = 32          # 32 bands x 4 rows -> candidate threshold ~(1/32)^(1/4) ~ 0.42
LSH_ROWS = N_HASHES // LSH_BANDS
LSH_THRESHOLD = 0.5     # final Jaccard cut

_MASK = (1 << 61) - 1   # Mersenne prime modulus for universal hashing
_RNG = random.Random(0xC0FFEE)
_HASH_PARAMS = [(_RNG.randrange(1, _MASK), _RNG.randrange(_MASK))
                for _ in range(N_HASHES)]


def word_shingles(text: str, k: int = SHINGLE_SIZE) -> list[int]:
    """Tokenize to words, hash each k-word shingle to a 61-bit int ONCE.

    One blake2b per shingle; the N_HASHES functions are cheap universal
    hashes (a*x+b mod p) over that base value — not N_HASHES full digests
    per shingle, which is ~100x slower for identical statistical behavior.
    """
    words = text.split()
    if len(words) < k:
        return []
    out = []
    for i in range(len(words) - k + 1):
        h = hashlib.blake2b(' '.join(words[i:i+k]).encode(), digest_size=8)
        out.append(int.from_bytes(h.digest(), 'big') & _MASK)
    return out


def minhash_signature(shingle_hashes: list[int]) -> list[int] | None:
    """MinHash signature; None for documents too short to shingle."""
    if not shingle_hashes:
        return None
    sig = []
    for a, b in _HASH_PARAMS:
        sig.append(min((a * x + b) % _MASK for x in shingle_hashes))
    return sig


def estimate_jaccard(sig_a: list[int], sig_b: list[int]) -> float:
    """ESTIMATE of Jaccard from signatures (stderr ~ 1/sqrt(N_HASHES) ~ 0.09)."""
    matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return matches / len(sig_a)


def restore_text(text: str) -> str:
    """Remove mechanical corruptions to approximate clean form.

    Removes: trailing spaces in strings, diff-marker prefixes, backtick booleans.
    This is a heuristic — it won't fix semantic corruption (3a-3g).
    """
    # Remove trailing spaces inside quoted strings
    text = re.sub(r'"(\w+)\s+"', r'"\1"', text)
    text = re.sub(r"'(\w+)\s+'", r"'\1'", text)
    # Remove diff-marker line prefixes
    text = re.sub(r'^[>!] ', '', text, flags=re.MULTILINE)
    text = re.sub(r'^<= ', '', text, flags=re.MULTILINE)
    text = re.sub(r'^>= ', '', text, flags=re.MULTILINE)
    # Remove backtick-wrapped booleans
    text = re.sub(r'`(true|false)`', r'\1', text)
    return text


def main():
    import argparse
    parser = argparse.ArgumentParser(description='MinHash dedup analysis')
    parser.add_argument('input', help='Input JSONL file')
    parser.add_argument('-o', '--output', default=None, help='Output JSON')
    parser.add_argument('--threshold', type=float, default=LSH_THRESHOLD,
                        help='Jaccard threshold for near-dedup')
    args = parser.parse_args()

    lines = Path(args.input).read_text().splitlines()
    samples = [json.loads(line) for line in lines]

    print(f"Loading {len(samples)} samples...")

    # Compute signatures
    signatures = []
    for i, s in enumerate(samples):
        text = s.get('text', '')
        restored = restore_text(text)
        signatures.append(minhash_signature(word_shingles(restored)))
        if (i+1) % 100 == 0:
            print(f"  {i+1}/{len(samples)}", flush=True)

    # LSH banding: a candidate pair must agree on ALL rows of some band.
    # (Bucketing on single hash values degenerates to near-all-pairs:
    # P(collision on any of 128 singles) is ~1 even at Jaccard 0.05.)
    buckets = defaultdict(list)
    for i, sig in enumerate(signatures):
        if sig is None:            # too short to shingle — never a candidate
            continue
        for band in range(LSH_BANDS):
            row = tuple(sig[band * LSH_ROWS:(band + 1) * LSH_ROWS])
            buckets[(band, row)].append(i)

    candidates = set()
    for indices in buckets.values():
        for i in range(len(indices)):
            for j in range(i+1, len(indices)):
                a, b = indices[i], indices[j]
                candidates.add((a, b) if a < b else (b, a))

    print(f"Candidate pairs: {len(candidates)}")

    # Estimated Jaccard for candidates (signature-based, +-0.09)
    pairs = []
    for (a, b) in candidates:
        j = estimate_jaccard(signatures[a], signatures[b])
        if j >= args.threshold:
            pairs.append({
                'a': a, 'b': b,
                'jaccard': round(j, 4),
                'index_a': samples[a]['index'],
                'index_b': samples[b]['index'],
                'size_a': samples[a]['size'],
                'size_b': samples[b]['size'],
                'type_a': samples[a].get('content_type', ''),
                'type_b': samples[b].get('content_type', ''),
                'first_a': samples[a]['first_line'][:60],
                'first_b': samples[b]['first_line'][:60],
            })

    # Build clusters (connected components)
    # Simple greedy: group by shared pairs
    clusters = []
    used = set()
    pair_list = [(p['a'], p['b']) for p in pairs]

    # Build adjacency
    adj = defaultdict(set)
    for a, b in pair_list:
        adj[a].add(b)
        adj[b].add(a)

    # BFS clusters
    for i in range(len(samples)):
        if i in used:
            continue
        cluster = []
        queue = [i]
        while queue:
            node = queue.pop(0)
            if node in used:
                continue
            used.add(node)
            cluster.append(node)
            for neighbor in adj[node]:
                if neighbor not in used:
                    queue.append(neighbor)
        if len(cluster) > 1:
            clusters.append(sorted(cluster))

    print(f"\nClusters (size>1): {len(clusters)}")
    for cluster in clusters[:10]:
        print(f"  Size {len(cluster)}: indices {cluster}")
        for idx in cluster[:3]:
            s = samples[idx]
            print(f"    Sample {s['index']}: {s['first_line'][:60]}")

    # Poison analysis per cluster
    print("\nCluster poison analysis:")
    poison_in_cluster = 0
    for cluster in clusters:
        poisoned = sum(1 for idx in cluster
                       if samples[idx].get('poisoned', False))
        if poisoned > 0:
            poison_in_cluster += 1
        # Check: does the cluster contain a mix of poisoned and clean?
        clean_in_cluster = len(cluster) - poisoned
        if poisoned > 0 and clean_in_cluster > 0:
            print(f"  MIXED cluster ({len(cluster)}): {poisoned} poisoned, "
                  f"{clean_in_cluster} clean")

    print(f"\nClusters containing at least one poisoned sample: "
          f"{poison_in_cluster}/{len(clusters)}")

    # Output
    if args.output:
        out = {
            'n_samples': len(samples),
            'threshold': args.threshold,
            'candidate_pairs': len(candidates),
            'near_duplicate_pairs': len(pairs),
            'clusters': len(clusters),
            'pairs': pairs[:100],  # limit output size
            'clusters_detail': [
                {'size': len(c), 'indices': c[:20],
                 'sample_indices': [samples[i]['index'] for i in c[:20]]}
                for c in clusters[:50]
            ]
        }
        Path(args.output).write_text(json.dumps(out, indent=2))
        print(f"\nSaved to {args.output}")


if __name__ == '__main__':
    main()
