# Hybrid PQ-CP-ABE Benchmark Suite

This benchmark is intended to replace the old average-only benchmark with a more reproducible methodology.

## What it measures

- AC17 and TKN20 native operations
  - Setup
  - KeyGen
  - Encrypt
  - Decrypt
- File I/O vs Buffer API
- ML-DSA-87 Sign-then-Encrypt overhead
- Isolated ML-DSA-87 KeyGen / Sign / Verify
- Isolated AES-256-GCM throughput
- Policy complexity scaling
- Payload size scaling
- Optional Charm-Crypto AC17 primitive reference

## Output

Each run creates a timestamped directory containing:

- raw_samples.csv
- summary.csv
- benchmark_results.json
- report.md
- charts/01_core_latency.png
- charts/02_decrypt_distribution.png
- charts/03_pqc_overhead.png
- charts/04_policy_scaling.png
- charts/05_payload_scaling.png
- charts/06_mldsa_latency.png
- charts/07_aes_gcm_throughput.png

Raw timing samples are retained. No outlier removal is performed.

## Published results

Curated benchmark snapshots intended for public review are stored under `published/`. These snapshots include the report, aggregate statistics, every raw timing sample, machine-readable JSON, and the generated charts.

Current published snapshot:

- `published/2026-10-25_i5-12450HX_standard/` — v5.2.0, Intel Core i5-12450HX, 100 timed iterations, 12-attribute policy, 4 KiB payload, AC17/TKN20 Buffer APIs, ML-DSA-87 Sign-then-Encrypt, and Charm-Crypto AC17 reference.

Timestamped directories under `results/` are local scratch runs and are intentionally ignored by Git.

## Install plotting/system dependencies

pip install -r requirements-benchmark.txt

Charm-Crypto is optional and is intentionally not placed in requirements because installation is platform-specific. If Charm cannot be imported, the script skips that reference suite.

## Run

Quick smoke benchmark:

python benchmark_full.py --profile quick --no-charm

Normal benchmark:

python benchmark_full.py --profile standard

Full publication-oriented run:

python benchmark_full.py --profile full

## Interpretation

Charm-Crypto is reported only as a reference primitive. Its AC17 API operates on a GT group element, while this library exposes a byte-oriented hybrid pipeline combining CP-ABE key protection, SHA3-256, and AES-GCM. Do not claim a universal N-times speedup solely from that comparison.

For publishable results, run the full profile on multiple machines and publish raw_samples.csv together with build/compiler information.
