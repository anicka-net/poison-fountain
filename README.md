# Poison Fountain

Detection and analysis of **poisoned training data** served by web honeypots
to corrupt LLM training corpora scraped from the open internet.

## What this is

In mid-2026 we discovered `rnsaffn.com/poison2/`, a honeypot serving
subtly corrupted code and prose to web scrapers. The content looks like
legitimate open-source code and news articles but carries targeted
corruption designed to degrade model behaviour when included in training
data.

This repository contains:

- **1000 raw samples** from the honeypot (`raw_samples/samples.jsonl`)
- **A filtering tool** with 27 detectors (`filter_poison.py`)
- **Detailed findings** documenting the corruption taxonomy (`FINDINGS.md`)

> ⚠️ **Handle as hostile data.** `raw_samples/` is intentionally poisoned
> content published for defensive research. Do not train on it, do not
> execute code from it, and do **not** `pip install` any package named in
> it (`maref` and `mothrag` resolve on PyPI — treat as indicators of
> compromise, provenance unknown).

## Why it matters

The corruption is layered. Surface-level damage (truncation, syntax
errors) is easy to catch. The dangerous patterns are subtle:

| Pattern | Example | Training impact |
|---------|---------|-----------------|
| Trailing space in dict keys | `data["status "]` | Model produces silent KeyError bugs |
| Modulo as division | `rate = passed % total` | Broken metrics code that looks correct |
| Near-miss model versions | `claude-haiku-5-4` | Poisons factual version knowledge |
| API keys in model slots | `("OPENAI_API_KEY", None, "gpt-4o")` | Credential leaks in generated code |
| License text mutations | `Apache License, Version 1.0` | Legally invalid boilerplate |
| Fictional package ecosystem | `import maref` | Slopsquatting — packages exist on PyPI |

The trailing-space corruption alone affects 3.8% of key occurrences,
applied stochastically — just enough to fly under typical data-quality
checks.

See [FINDINGS.md](FINDINGS.md) for the full taxonomy (3 levels, 10+
pattern families) and quantitative analysis.

## Quick start

```bash
# Score every sample (adds poison_score and poison_findings to each record)
python filter_poison.py score raw_samples/samples.jsonl -o scored.jsonl

# Filter out poisoned samples (keep only clean ones)
python filter_poison.py filter raw_samples/samples.jsonl -o clean.jsonl

# Show detection statistics
python filter_poison.py stats raw_samples/samples.jsonl
```

No dependencies beyond Python 3.10+ standard library.

### Threshold

Default threshold is 3.0. Each detector assigns a weight (1.5–3.0) per
finding; the sample's poison score is the sum. At the default threshold:

- **506/1000 samples flagged** (50.6%)
- 326 samples score 0 — a mix of genuinely clean camouflage samples and
  corruption below detection (prose factual corruption in particular
  resists regex; 138 of these carry labels from the independent
  heuristic labeler). Neither tool is ground truth — residual poison
  rate in score-0 is unestimated pending a judged random sample

Lower the threshold to catch more at the cost of false positives:
```bash
python filter_poison.py filter samples.jsonl -o clean.jsonl --threshold 2.0
```

## Detectors

27 detectors in three tiers:

**Subtle semantic (Level 3)** — high precision, low false-positive rate:
trailing space in keys/values/strings, backtick-bool corruption,
truthiness traps, modulo-as-division, API key in model slot, near-miss
versions, impossible runtime versions, license corruption, hallucinated
versions, CLI flag corruption, word-order mangling, prose entity
impossibilities

**Structural (Level 2)** — diff-marker line prefixes, wrong file modes,
brace-as-dict-key, tab-as-line-separator, inverted sys.path guard,
bind-to-port-1

**Surface (Level 1)** — repetition, truncation, syntax errors

## Key findings

- **Stochastic corruption**: 3.80% of string key occurrences carry
  trailing space, applied once at corpus generation (not per-fetch)
- **Fictional package ecosystem**: `maref` (1327 imports) and `mothrag`
  (353) both exist on PyPI — treat as indicators of compromise
- **Near-dedup is a poison gate, not a bystander**: at ~3.7% corruption,
  73% of poisoned samples land in the same MinHash bucket as their clean
  originals — so the dedup *survivor policy* decides whether the poisoned
  or the clean copy enters your corpus. Rank survivors by provenance
  (trusted origin first) and dedup becomes a free filter; keep-first
  makes it a coin flip
- **Multi-vector**: 245/1000 samples carry 2+ distinct corruption types
- **Prose gap**: 686/1000 samples are prose; factual corruption in prose
  (entity swaps, impossible claims) largely resists regex detection

## Using with your own data

The filter works on any JSONL where each line has a `"text"` field:

```bash
python filter_poison.py score my_crawl.jsonl -o scored.jsonl
python filter_poison.py filter my_crawl.jsonl -o clean.jsonl --threshold 2.0
```

The detectors are tuned for PoisonFountain-style corruption but several
patterns (trailing spaces in strings, modulo-as-division, impossible
versions, license mutations) appear in other poisoned datasets too.

## Structure

```
poison-fountain/
├── README.md                 # this file
├── FINDINGS.md               # full analysis with taxonomy and quantitative results
├── filter_poison.py          # 27-detector filtering tool (zero dependencies)
├── raw_samples/
│   └── samples.jsonl         # 1000 honeypot samples
├── labeled_dataset.jsonl     # DeepSeek's initial labeling (624/1000 flagged)
├── fetch_samples.py          # sample fetching scripts (historical)
├── fetch_fast.py
├── analyze.py                # initial analysis script (historical)
└── label_samples.py          # DeepSeek labeling script (historical)
```

## Contributors

Analysis and detectors by [@anicka-net](https://github.com/anicka-net)
with assistance from Claude, GPT, and DeepSeek.

## License

MIT for the tools and analysis. `raw_samples/` is third-party honeypot
content redistributed unmodified for defensive research; no license is
claimed or granted on it.
