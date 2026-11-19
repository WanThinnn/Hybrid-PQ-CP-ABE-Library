# PQ-CP-ABE Python SDK

- PyPI distribution: `pq-cp-abe`
- Import: `import pq_cp_abe`
- The repository root `VERSION` is the sole build version; installed packages read the embedded distribution metadata.
- All 33 DLL exports listed for v6.0.1 have declared `ctypes` signatures and can be accessed as `pq_cp_abe.native.<C_symbol>`; low-level native buffers require `native.freeBuffer`. Python-friendly wrappers are provided for the additional AES-GCM, ML-DSA-87, setup/genkey buffer and CoverCrypt authority operations.
- Run `python bindings/python/hybrid_pq_cp_abe.py --test` or `python -m pq_cp_abe --test` for an end-to-end, disposable Python-only self-test. It invokes all 33 native symbols, verifies roundtrips across AC17/TKN20/CoverCrypt, AES-GCM, ML-DSA and CoverCrypt authority updates. It does not build C++ or modify application keys; the temporary test files are removed automatically. Exit code 0 means PASS; a nonzero code means FAIL.

## Layout

`pq_cp_abe/_native.py` handles `ctypes` loading and the C ABI, `api.py` exposes the existing Python API, `__main__.py` implements the CLI, and `_libs/` holds the bundled native runtimes.

## Native GitHub Release as the binary source

`.github/workflows/publish-pypi.yml` uses *already published* native ZIPs from the exact `v<VERSION>` GitHub Release. It does **not** build C++, Rust or Go and does **not** use local `lib/` or `build/artifacts/` output. `stage_native.py` downloads the release's `SHA256SUMS.txt`, verifies the archive's SHA-256 and extracts only runtime binaries.

| OS | Architecture | Required runtime |
| --- | --- | --- |
| Windows | x86_64 | `libhybrid-pq-cp-abe.dll` and `libcpabe_tkn20.dll` |
| Linux | x86_64 | `libhybrid-pq-cp-abe.so` |
| macOS Intel | x86_64 | `libhybrid-pq-cp-abe.dylib` |
| macOS Apple Silicon | arm64 | `libhybrid-pq-cp-abe.dylib` |

The wheel is platform-specific and uses Python-independent `py3-none-<platform>` tags. Linux wheels are repaired/audited with `auditwheel` for manylinux; macOS wheels use `delocate`. Different macOS architectures are separate wheels, not incorrectly marked universal2. Windows wheels require both DLLs.

## Build/check on CI

From the repository on the matching GitHub Actions runner:

```sh
python bindings/python/stage_native.py --platform windows --arch x86_64
python -m pip install build
python -m build --wheel bindings/python
python bindings/python/verify_wheel.py --wheel-dir bindings/python/dist
```

Substitute `windows/x86_64` with the actual runner target. On Linux/macOS, repair the wheel before calling `verify_wheel.py`, as in the workflow.

Staging also copies the project license, notice, and third-party licenses
from the verified native release. The wheel ships those files in its
`.dist-info/licenses/` directory.

The verifier installs the wheel outside the source checkout, checks its internal native files and version, and runs AC17/TKN20/CoverCrypt setup, user key generation and encrypt/decrypt roundtrips. **Do not use a local cached binary to judge a GitHub Release.**

## Publishing

From GitHub Actions, run **Build Python Wheels** with the `publish` input set to `false` to build/test/download the wheel artifacts only.

Once all four jobs pass, configure a PyPI *Trusted Publisher* for this GitHub repository, workflow `publish-pypi.yml`, and environment `pypi`. Then manually dispatch the workflow with `publish=true`. This is opt-in: no deployment occurs on ordinary pushes or releases.

The existing native `release.yml` is unchanged and Python publishing is independent. Source distribution (`sdist`) is intentionally not published because it cannot install a functioning native runtime by itself.

For local source development, the SDK can still fall back to the repository's `lib/` binaries when available. This is separate from GitHub Release staging for wheels.

Compatibility entrypoints `bindings/python/hybrid_pq_cp_abe.py` and `bindings/python/test_api.py` remain, while new callers should use `pq_cp_abe`.
