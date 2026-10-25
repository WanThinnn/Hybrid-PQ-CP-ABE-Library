# Published Benchmark — 2026-10-25

This directory contains a reproducible benchmark snapshot for Hybrid PQ-CP-ABE Library v5.2.0.

## Environment

- CPU: 12th Gen Intel(R) Core(TM) i5-12450HX
- OS: Windows 10 build 26300
- Python: 3.10.8, 64-bit
- Native library: v5.2.0
- Git commit: 320137296b8fc1a240a5580c24c410fa8ec6e6f5
- Benchmark profile: standard
- Timed iterations: 100
- Warm-up iterations: 5
- Payload: 4 KiB
- Policy: 12 distinct attributes

## Included artifacts

- `report.md` — methodology, environment, summary tables, and interpretation notes.
- `summary.csv` — aggregated median/mean/p95/p99/CV statistics.
- `raw_samples.csv` — every recorded timing sample; no outlier removal.
- `benchmark_results.json` — machine-readable benchmark metadata and aggregate records.
- `charts/` — publication-ready benchmark figures.

## Scope

The native AC17 and TKN20 measurements use the in-memory Buffer API.

The PQC measurements cover the end-to-end Sign-then-Encrypt path using ML-DSA-87.

Charm-Crypto AC17 is included as an in-memory primitive reference. It is not a strict end-to-end equivalent of the native hybrid pipeline: Charm operates on a GT group element, while the native library protects a random secret with CP-ABE and uses AES-GCM for payload encryption.

Therefore, this snapshot should not be used to claim a universal N-times speedup versus Charm across all operations. The raw samples are included so results can be independently inspected.

## Reproduce

From the repository `benchmark/` directory:

```bash
python showcase_benchmark.py --profile standard
```

For a broader benchmark including File I/O, scaling tests, AES-GCM, and additional microbenchmarks:

```bash
python benchmark_full.py --profile full
```
