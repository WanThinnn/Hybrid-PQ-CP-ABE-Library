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

Focused showcase benchmark (automatically writes to `published/<date>_<cpu>_<profile>`):

python benchmark_full.py --profile standard --showcase

Use `--output <path>` only when you want to override the automatic published path.

CoverCrypt uses at most two native dimensions: policy terms are ORed within
each dimension and the dimensions are ANDed together. This is a different
policy shape from the AC17/TKN20 all-attribute AND policy. Do not interpret
equal attribute counts as equivalent access policies across these schemes.
Giving every term its own CoverCrypt dimension causes a combinatorial growth
in setup work and can make the benchmark appear to hang.

At startup, check the printed CoverCrypt configuration: the default
12-attribute showcase should report `2 dimension(s)`. Each new run generates
its own configuration; after updating the script, stop any older benchmark
process and start a fresh run. The generated dimensions are also saved in
`benchmark_results.json`, even after the temporary configuration is removed.

Run the configuration and native CoverCrypt showcase regression checks with:

```bash
python -m unittest discover -s benchmark -p test_benchmark_full.py -v
```

Run that command from the repository root. Native checks require a built
library and the plotting dependencies above; each subprocess has a timeout.

Full publication-oriented run:

python benchmark_full.py --profile full

## Interpretation

Charm-Crypto is reported only as a reference primitive. Its AC17 API operates on a GT group element, while this library exposes a byte-oriented hybrid pipeline combining CP-ABE key protection, SHA3-256, and AES-GCM. Do not claim a universal N-times speedup solely from that comparison.

For publishable results, run the full profile on multiple machines and publish raw_samples.csv together with build/compiler information.
