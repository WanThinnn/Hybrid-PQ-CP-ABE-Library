# Hybrid PQ-CP-ABE Benchmark Suite

This directory is the canonical benchmark location for the project. The old
`bindings/python/benchmark.py` benchmark has been removed so benchmark logic is
not duplicated across the repository.

`benchmark_full.py` is the single benchmark entrypoint and source of truth.
Use `--showcase` for the focused public/LinkedIn subset.

## What it measures

- AC17, TKN20, and CoverCrypt native operations
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
- 4-way ABE key-protection comparison: AC17, TKN20, CoverCrypt Hybridized, and Charm-Crypto AC17
  - Native schemes protect/recover the same 32-byte key material
  - Charm-Crypto AC17 remains a GT-element reference

## Output

Each run creates a timestamped directory containing:

- raw_samples.csv
- summary.csv
- benchmark_results.json
- covercrypt_config.json
- report.md
- charts/00_abe_primitive_comparison.png
- charts/00_abe_primitive_comparison_log.png
- charts/01_core_latency.png
- charts/01_core_latency_log.png
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

Build the benchmark-only native primitive bridge first:

```bash
make benchmark-bridge
```

On Windows this compiles only `benchmark/native_primitive_bridge.cpp` and links it against the already-built artifacts under `build/artifacts/windows` and `build/deps/windows`. It does **not** rebuild the core library or dependencies.

Quick smoke benchmark:

python benchmark_full.py --profile quick --no-charm

Normal benchmark:

python benchmark_full.py --profile standard

Focused showcase benchmark (automatically writes to `published/<date>_<cpu>_<profile>`):

python benchmark_full.py --profile standard --showcase --covercrypt-dimensions 4

Use `--output <path>` only when you want to override the automatic published path.

CoverCrypt defaults to four native dimensions (`--covercrypt-dimensions 4`).
Logical policy terms are distributed as evenly as possible across them, ORed
within each dimension, and the dimensions are ANDed together. For the default
12-term showcase this produces 4 dimensions × 3 values. This is a different
policy shape from the AC17/TKN20 all-attribute AND policy; equal term counts do
not mean equivalent access policies. Giving every term its own CoverCrypt
dimension causes combinatorial growth in the rights universe and setup work.

At startup, check the printed CoverCrypt configuration: the default 12-term
showcase should report `4 dimension(s)`. Each run persists the exact generated
configuration as `covercrypt_config.json` in its output directory and records
the dimensions plus the estimated rights-universe size in `benchmark_results.json`.

Run the configuration and native CoverCrypt showcase regression checks with:

```bash
python -m unittest discover -s benchmark -p test_benchmark_full.py -v
```

Run that command from the repository root. Native checks require a built
library and the plotting dependencies above; each subprocess has a timeout.

Full publication-oriented run:

python benchmark_full.py --profile full

## Interpretation

The public comparison chart uses the benchmark-only primitive bridge for AC17, TKN20, and CoverCrypt. Those three native backends all protect/recover the same 32-byte key material. CoverCrypt runs in hybridized mode (Curve25519 + ML-KEM-768) and its adapter uses the KEM shared secret with AES-GCM to wrap that key material. Charm-Crypto AC17 operates on a GT element, so it remains a reference rather than a byte-for-byte equivalent. Do not claim a universal N-times speedup without this scope note.

For publishable results, run the full profile on multiple machines and publish raw_samples.csv together with build/compiler information.
