# PQ-CP-ABE Python SDK

- PyPI distribution: `pq-cp-abe`
- Import: `import pq_cp_abe`
- The repository root `VERSION` is the sole build version; installed packages read the embedded distribution metadata.
- All 33 public C exports have declared `ctypes` signatures and can be accessed as `pq_cp_abe.native.<C_symbol>`; low-level native buffers require `native.freeBuffer`. Python-friendly wrappers are provided for the additional AES-GCM, ML-DSA-87, setup/genkey buffer and CoverCrypt authority operations.
- Run `python bindings/python/hybrid_pq_cp_abe.py --test` or `python -m pq_cp_abe --test` for an end-to-end, disposable Python-only self-test. It invokes all 33 native symbols, verifies roundtrips across AC17/TKN20/CoverCrypt, AES-GCM, ML-DSA and CoverCrypt authority updates. It does not build C++ or modify application keys; the temporary test files are removed automatically. Exit code 0 means PASS; a nonzero code means FAIL.

## Quick start

Install the package on Python 3.10 or later once the wheel is published to PyPI.
You can also install the wheel for your platform directly from GitHub Releases
with `python -m pip install <downloaded-wheel.whl>`.

```sh
python -m pip install pq-cp-abe
```

### Basic CLI commands

Run `python -m pq_cp_abe` to list commands and `python -m pq_cp_abe --test`
to run the full self-test. CoverCrypt is the default for the CLI and Python
wrappers, and setup requires a dimensions JSON file. The examples below
explicitly select AC17 so they can run in a new working directory without a
CoverCrypt configuration file.

```sh
mkdir keys
python -c "from pathlib import Path; Path('message.txt').write_text('Hello from PQ-CP-ABE', encoding='utf-8')"
python -m pq_cp_abe --scheme ac17 setup keys
python -m pq_cp_abe --scheme ac17 genkey keys/cpabe_msk.key "admin it" keys/user.key
python -m pq_cp_abe --scheme ac17 encrypt keys/cpabe_pk.key message.txt "admin and it" message.enc
python -m pq_cp_abe decrypt keys/user.key message.enc recovered.txt
python -c "from pathlib import Path; print(Path('recovered.txt').read_text(encoding='utf-8'))"
```

The policy requires both attributes. Setup creates the authority's master
secret key (`cpabe_msk.key`) and public key (`cpabe_pk.key`). Use the master
secret key to issue user keys, and share the public key with encryptors.

For optional ML-DSA-87 signing and verification, use a separate key directory
and the same `message.txt`.

```sh
mkdir signed-keys
python -m pq_cp_abe --scheme ac17 setup-pqc signed-keys
python -m pq_cp_abe --scheme ac17 genkey signed-keys/cpabe_msk.key "admin it" signed-keys/user.key
python -m pq_cp_abe --scheme ac17 encrypt-pqc signed-keys/cpabe_pk.key signed-keys/pqc_sk.key message.txt "admin and it" signed.enc
python -m pq_cp_abe decrypt-pqc signed-keys/user.key signed-keys/pqc_pk.key signed.enc verified.txt
```

### Run a Python example

Copy this into `demo.py` and run `python demo.py`. It creates an authority,
issues a user key, and encrypts and decrypts a message in memory using the
default CoverCrypt scheme.

```python
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pq_cp_abe as abe


def main():
    attributes = "admin it"
    policy = "admin and it"
    message = b"Hello from PQ-CP-ABE"

    with TemporaryDirectory() as directory:
        config = Path(directory) / "covercrypt.json"
        config.write_text(json.dumps({"dimensions": [
            {"name": "admin", "attributes": ["present", "absent"]},
            {"name": "it", "attributes": ["present", "absent"]},
        ]}), encoding="utf-8")
        os.environ["HCPABE_COVERCRYPT_CONFIG"] = str(config)

        public_key, master_key = abe.setup_buffer()
        user_key = abe.genkey_buffer(master_key, attributes)
        ciphertext = abe.call_hybrid_cpabe_encryptBuffer(public_key, message, policy)
        recovered = abe.call_hybrid_cpabe_decryptBuffer(user_key, ciphertext)
    if recovered != message:
        raise RuntimeError("The decrypted message does not match the original")

    print(f"Native library version: {abe.get_version()}")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(recovered.decode("utf-8"))


if __name__ == "__main__":
    main()
```

For existing AC17 or TKN20 keys, pass `scheme=abe.CPABE_SCHEME_AC17` or
`scheme=abe.CPABE_SCHEME_TKN20` to setup, key generation and encryption.
Decryption detects the scheme from the ciphertext. For CoverCrypt CLI setup,
set `HCPABE_COVERCRYPT_CONFIG` to a dimensions JSON file and omit `--scheme`.
See the [scheme guide](../../docs/architecture.md#native-pqc-with-covercrypt).

## Layout

`pq_cp_abe/_native.py` handles `ctypes` loading and the C ABI, `api.py` exposes the existing Python API, `__main__.py` implements the CLI, and `_libs/` holds the bundled native runtimes.

## Native GitHub Release as the binary source

`.github/workflows/publish-pypi.yml` uses *already published* native ZIPs from the exact `v<VERSION>` GitHub Release. It does **not** build C++, Rust or Go and does **not** use local `lib/` or `build/artifacts/` output. `stage_native.py` verifies the archive against the release's `SHA256SUMS.txt` and stages the runtime binaries and license files.

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
