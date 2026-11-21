# Published Benchmark — 2026-11-21

This directory contains a reproducible benchmark snapshot for Hybrid PQ-CP-ABE Library v6.1.0.

## Environment

- CPU: 12th Gen Intel(R) Core(TM) i5-12450HX
- OS: Windows-10-10.0.26300-SP0
- Python: 3.10.8 (tags/v3.10.8:aaaf517, Oct 11 2022, 16:50:30) [MSC v.1933 64 bit (AMD64)]
- Native library: v6.1.0
- Git commit: 6afe9efb73171677a0632d23b2d3ceec93f8b26b
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
python main.py --profile standard --showcase --iterations 100 --warmup 5 --payload-bytes 4096 --policy-attributes 12 --covercrypt-dimensions 4 --seed 2026 --no-file --no-scaling --require-charm
```

For a broader benchmark including File I/O, scaling tests, AES-GCM, and additional microbenchmarks:

```bash
python main.py --profile full
```
