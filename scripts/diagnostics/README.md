# Local CoverCrypt diagnostics

Run from the repository root after building the native library and dependencies:

```sh
python scripts/diagnostics/analyze_covercrypt_cost.py
python scripts/diagnostics/measure_covercrypt_genkey.py
```

The first script measures Classic/Hybridized setup with bounded per-case
subprocesses and checks access-policy behavior. It uses the project native
library under `lib/`. The second compares persisted and ephemeral KeyGen through
the standalone shared C ABI under `build/deps/<platform>/lib/covercrypt/`.

Results go into `build/reports/covercrypt/`. No key material is written to the
reports. These are local diagnostic measurements, not publication benchmarks.
For the full benchmark suite, use `benchmark/benchmark_full.py`.
