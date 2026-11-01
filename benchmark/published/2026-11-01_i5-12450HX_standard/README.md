# Published Benchmark — 2026-11-01

This directory contains a reproducible benchmark snapshot for Hybrid PQ-CP-ABE Library v6.0.0.

## Environment

- CPU: 12th Gen Intel(R) Core(TM) i5-12450HX
- OS: Windows-10-10.0.26300-SP0
- Python: 3.10.8 (tags/v3.10.8:aaaf517, Oct 11 2022, 16:50:30) [MSC v.1933 64 bit (AMD64)]
- Native library: v6.0.0
- Git commit: 4fb3f113b687d643b0ca25d62ceff2e0664bb08d
- Benchmark profile: standard
- Timed iterations: 100
- Warm-up iterations: 5
- Payload: 4.00 KiB
- Policy terms: 12
- CoverCrypt dimensions: 4 (requested 4)
- CoverCrypt rights-universe estimate: 256
- Mode: showcase

## Included artifacts

- `report.md` — methodology, environment, summary tables, and interpretation notes.
- `summary.csv` — aggregated median/mean/p95/p99/CV statistics.
- `raw_samples.csv` — every recorded timing sample; no outlier removal.
- `benchmark_results.json` — machine-readable benchmark metadata and aggregate records.
- `covercrypt_config.json` — persisted CoverCrypt dimensions used by this run.
- `charts/` — generated benchmark figures.

## Scope

AC17, TKN20, and CoverCrypt use the in-memory Buffer API. CoverCrypt runs in hybridized mode (Curve25519 + ML-KEM-768).

The PQC measurements cover the end-to-end Sign-then-Encrypt path using ML-DSA-87.

Charm-Crypto AC17 is included as the GT-element reference in the primitive-comparison suite. Native AC17/TKN20/CoverCrypt protect the same 32-byte key material.

## Reproduce

From the repository `benchmark/` directory:

```bash
python benchmark_full.py --profile standard --showcase --covercrypt-dimensions 4
```

For a broader benchmark including File I/O, scaling tests, AES-GCM, and additional microbenchmarks:

```bash
python benchmark_full.py --profile full
```
