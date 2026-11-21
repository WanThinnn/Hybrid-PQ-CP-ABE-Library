# Hybrid PQ-CP-ABE Benchmark Suite

`main.py` is the only benchmark CLI. The implementation lives in `src/`:

| Module | Responsibility |
| --- | --- |
| `config.py` | Profiles, policies, bounded CoverCrypt dimensions |
| `native.py` | Python bindings, version checks and scheme objects |
| `timing.py` | Warmup, timing, GC and native log suppression |
| `records.py` | Raw samples and aggregate statistics |
| `suites.py` | Native/Charm comparison, core, signing, primitives and scaling |
| `environment.py` | Machine, library, binding and Git metadata |
| `charts.py` | Figures using only available measurements |
| `reports.py` | CSV, JSON, Markdown and snapshot README |
| `cli.py` | Arguments, suite selection and publication workflow |

## Python API 6.1

The benchmark uses the public [Python API reference](https://wanthinnn.github.io/pq-cp-abe/bindings/python/api/)
and its implementation in `bindings/python/pq_cp_abe/`:

- `AC17CPABE`, `TKN20CPABE`, `CoverCryptABE`: `setup`, `keygen`, `encrypt`,
  `setup_with_signing` and `encrypt_and_sign`, with modern functional `decrypt`
  and `decrypt_and_verify` to recover ciphertexts carrying their scheme ID.
- Modern file operations: `setup_files`, `generate_secret_key_file`,
  `encrypt_file`, `decrypt_file`.
- `MlDsa(ML_DSA_87)` and `AesGcm(256)` for standalone primitives.

There are no benchmark-owned `ctypes` calls, legacy `call_*` operations or C++
primitive bridge calls. `make benchmark-bridge` is no longer needed.
Both the native library and Python bindings must be version 6.1 or newer.
The public `get_version()` accessor is used only for version metadata.

In this checkout the CLI imports source bindings from `bindings/python`.
Their normal loader selects the bundled `_libs` library first, then the repository
`lib/` library. Keep built 6.1 binaries and runtime dependencies in the location
expected by that loader. The loaded path and both versions are saved in JSON.
The old `--lib` and `--primitive-bridge` options were removed; library loading
belongs to the Python package.

## Installation

From the repository root, with the native 6.1 library already built:

```powershell
python -m pip install -r benchmark/requirements-benchmark.txt
```

Charm-Crypto requires a separate platform-specific installation in the **same
Python environment**. The four-way command uses `--require-charm` to fail before
measurements if AC17 dependencies cannot be imported. Without that flag, an
unavailable reference is skipped and reported. Use `--no-charm` only when
intentionally measuring the three native schemes.

## Run

All commands run from the repository root. Running without `--help` performs
real measurements; tests do not automatically run benchmarks.

Focused four-way comparison plus buffer operations, signing overhead and ML-DSA:

```powershell
python benchmark/main.py --profile standard --showcase --covercrypt-dimensions 4 --require-charm
```

Full suite, including file I/O, policy/payload scaling and AES-GCM throughput:

```powershell
python benchmark/main.py --profile full --covercrypt-dimensions 4 --require-charm
```

Short native-only run:

```powershell
python benchmark/main.py --profile quick --no-charm
```

`python benchmark/main.py --help` inspects options without loading native code.
`--iterations` overrides core/comparison counts; microbenchmarks and scaling
retain their profile counts. `--warmup` applies to every suite. `--showcase`
excludes file I/O, scaling and AES throughput. `--no-primitive` excludes the
native 32-byte comparison; combine with `--no-charm` to omit that chart entirely.

## Output and published snapshots

Every profile defaults to a new directory under:

```text
benchmark/published/<date>_<cpu>_<profile>_<timestamp>/
```

Use `--output <empty-directory>` to override it. Nonempty directories are rejected
so historical snapshots cannot be overwritten by a rerun. Each completed run writes:

- `README.md`: environment, scope and reproduction command.
- `report.md`: methodology, findings, tables and generated chart links.
- `raw_samples.csv`: every timed sample; no outlier removal.
- `summary.csv`: count, min/mean/median/p95/p99/max, standard deviation, CV and
  a normal-approximation 95% confidence interval for the mean.
- `benchmark_results.json`: environment, effective configuration and records.
- `covercrypt_config.json`: exact dimensions used by the run.
- `charts/`: comparison (linear/log), core latency (linear/log), decrypt
  distribution, signature overhead, policy/payload scaling, ML-DSA and AES
  throughput figures, according to enabled suites.

Existing `published/` snapshots are preserved historical measurements.
The `primitive_compare` suite and `00_abe_primitive_comparison*.png` filenames
remain stable for consumers; the native variant is now `hybrid_32_bytes`.
New measurements include Python API overhead and must not be merged with old
C++ bridge timings as though their scope were identical. New results are only
produced when you run the CLI.

## Interpretation

Native AC17, TKN20 and CoverCrypt encrypt/recover the same 32-byte input using
the modern Python **hybrid encryption API**, including Python validation and
conversion, serialization, key derivation and symmetric encryption overhead.
Charm-Crypto AC17 uses `PairingGroup("BN254")`, assumption size 2, and encrypts a
GT element. It is a reference, not an equivalent byte-oriented hybrid pipeline
or an isolated native ABE primitive comparison.

AC17/TKN20/Charm use an AND policy with the requested logical term count.
CoverCrypt runs hybridized mode (Curve25519 + ML-KEM-768); terms are distributed
evenly across at most four dimensions by default, ORed inside each dimension
and ANDed across dimensions. Equal counts do not mean equivalent access policies.
The default 12-term baseline has four dimensions with three values each.
This bound avoids exponential setup growth from one dimension per term.
The full profile configures enough values for its largest scaling case.

Warmups are discarded, GC is disabled only in timed loops, and timers wrap only
the API call. Log redirection and progress output are outside the timer.
AES encryption pre-generates fresh nonces for every warmup/timed call; nonce
generation is excluded. All cryptographic suites check their output before
publication. File mode includes disk I/O. Results depend on machine, build,
cache, thermal state and background load.

## Checks without running a benchmark

```powershell
python benchmark/main.py --help
python -m unittest discover -s benchmark -p test_benchmark.py -v
```

Checks use pure configuration, synthetic report data and mocked API calls;
they do not load native cryptography or take benchmark measurements.
