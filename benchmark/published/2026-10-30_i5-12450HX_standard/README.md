# Published Benchmark — 2026-10-30

This directory contains a reproducible benchmark snapshot for Hybrid PQ-CP-ABE Library v5.2.1.

## Environment

- CPU: 12th Gen Intel(R) Core(TM) i5-12450HX
- OS: Windows-10-10.0.26300-SP0
- Python: 3.10.8 (tags/v3.10.8:aaaf517, Oct 11 2022, 16:50:30) [MSC v.1933 64 bit (AMD64)]
- Native library: v5.2.1
- Git commit: b4cced2e539ac5d17dfdf9fa5f5990339454a0bd
- Benchmark profile: standard
- Timed iterations: 100
- Warm-up iterations: 5
- Payload: 4.00 KiB
- Policy: 12 distinct attributes
- Mode: showcase

## Included artifacts

- `report.md` — methodology, environment, summary tables, and interpretation notes.
- `summary.csv` — aggregated median/mean/p95/p99/CV statistics.
- `raw_samples.csv` — every recorded timing sample; no outlier removal.
- `benchmark_results.json` — machine-readable benchmark metadata and aggregate records.
- `charts/` — generated benchmark figures.

## Scope

AC17, TKN20, and CoverCrypt use the in-memory Buffer API. CoverCrypt runs in hybridized mode (Curve25519 + ML-KEM-768).

The PQC measurements cover the end-to-end Sign-then-Encrypt path using ML-DSA-87.

Charm-Crypto AC17 is included as an in-memory primitive reference. It is not a strict end-to-end equivalent of the native hybrid pipeline.

## Reproduce

From the repository `benchmark/` directory:

```bash
python benchmark_full.py --profile standard --showcase
```

For a broader benchmark including File I/O, scaling tests, AES-GCM, and additional microbenchmarks:

```bash
python benchmark_full.py --profile full
```
