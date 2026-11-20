# PQ-CP-ABE Python SDK

## Modern Python API (additive)

New integrations can use `setup`, `generate_secret_key`, `encrypt`, and
`decrypt` directly. Existing `call_*`, buffer helpers, constants, and `native`
remain available with their original signatures, return values and errors.
There are no deprecation warnings or automatic migrations.

With the CoverCrypt configuration described below already set through
`HCPABE_COVERCRYPT_CONFIG`:

```python
import pq_cp_abe as abe

keys = abe.setup()  # Default: Scheme.COVERCRYPT
secret_key = abe.generate_secret_key(
    master_secret_key=keys.master_secret_key,
    attributes="role::admin department::finance",
)
ciphertext = abe.encrypt(
    public_key=keys.public_key,
    plaintext=b"Hello",
    policy="role::admin && department::finance",
)
assert abe.decrypt(secret_key=secret_key, ciphertext=ciphertext) == b"Hello"
```

Pass `scheme=abe.Scheme.AC17` or `abe.Scheme.TKN20` consistently to setup,
key generation and encryption to use those schemes. Decryption detects the
ciphertext scheme. Each scheme retains its native attribute/policy syntax.

| In-memory API | File API |
| --- | --- |
| `setup()` | `setup_files(output_path)` |
| `setup_with_signing()` | `setup_files_with_signing(output_path)` |
| `generate_secret_key(...)` | `generate_secret_key_file(...)` |
| `encrypt(...)` / `decrypt(...)` | `encrypt_file(...)` / `decrypt_file(...)` |
| `encrypt_and_sign(...)` | `encrypt_and_sign_file(...)` |
| `decrypt_and_verify(...)` | `decrypt_and_verify_file(...)` |

In-memory operations accept/return `bytes`; the binding copies and frees C
output buffers even on failure. `setup()` returns `AuthorityKeys` with
`public_key` and `master_secret_key` fields (also tuple-unpackable).
`setup_with_signing()` adds `verification_key` and `signing_key`, in the native
Base64-encoded byte format expected by the combined signing operations.
These differ from the raw key bytes used by standalone `ml_dsa_87_*` helpers.
File operations accept `str` or `PathLike[str]` and return `None` on success;
setup retains native directory/prefix naming. The new wrappers add no console
output, although native file functions may still write logs.

New API native failures raise `AbeError` with `.code` and `.operation`;
native codes -3 and -9 map to `PolicyMismatchError` and `SignatureInvalidError`.
Other native failures remain `AbeError`, including -4 for a generic
cryptographic failure. Invalid Python inputs raise `TypeError`/`ValueError`.
The package ships annotations and a `py.typed` marker.

The public API uses functions and small data types, with no stateful crypto
class required. A future context object can hold configuration and delegate
to these same functions without breaking callers. Raw key bytes remain
application-owned; Python does not guarantee secure erasure of immutable bytes.

Encrypt data under a policy such as `role::admin && department::finance`.
Only a user whose key grants the admin role in the finance department can
decrypt it. This is
**ciphertext-policy attribute-based encryption (CP-ABE)**.

The default scheme, **CoverCrypt**, brings **post-quantum protection to ABE
key encapsulation**. Its default `hybridized` mode combines Curve25519 and
ML-KEM-768 to protect the secret used for AES-256-GCM payload encryption.
Optional ML-DSA-87 signatures authenticate the sender and signed data.
AC17 and TKN20 use classical ABE key protection, including when signing
is enabled.

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

### Post-quantum ABE from the CLI

Run `python -m pq_cp_abe` to list commands and `python -m pq_cp_abe --test`
to run the full self-test. The demo uses CoverCrypt in its default
`hybridized` mode. Here, **hybrid means Curve25519 and ML-KEM-768 each
contribute a shared secret to the same key encapsulation**. CoverCrypt uses
both components to recover the protected secret, while AES-256-GCM encrypts
the file itself. For ML-KEM-768-only encapsulation, see
[how to choose `post_quantum`](#choose-hybrid-or-pqc-only-key-encapsulation).

In a new working directory, create a file named `attributes-dimensions.json`:

```json
{
  "dimensions": [
    {"name": "role", "attributes": ["admin", "analyst"]},
    {"name": "department", "attributes": ["finance", "engineering"]}
  ]
}
```

Set `HCPABE_COVERCRYPT_CONFIG` in the terminal where you will run the demo.
Set `HCPABE_COVERCRYPT_MODE` to `hybridized` if the terminal already uses
another mode.

- Bash: `export HCPABE_COVERCRYPT_CONFIG=./attributes-dimensions.json`
- PowerShell: `$env:HCPABE_COVERCRYPT_CONFIG = (Resolve-Path ./attributes-dimensions.json).Path`
- CMD: `set "HCPABE_COVERCRYPT_CONFIG=%CD%\attributes-dimensions.json"`

```sh
mkdir keys
python -c "from pathlib import Path; Path('message.txt').write_text('Hello from PQ-CP-ABE', encoding='utf-8')"
python -m pq_cp_abe setup keys
python -m pq_cp_abe genkey keys/cpabe_msk.key "role::admin department::finance" keys/user.key
python -m pq_cp_abe encrypt keys/cpabe_pk.key message.txt "role::admin && department::finance" message.enc
python -m pq_cp_abe decrypt keys/user.key message.enc recovered.txt
python -c "from pathlib import Path; print(Path('recovered.txt').read_text(encoding='utf-8'))"
```

CoverCrypt writes each attribute as `dimension::value`. Pass a
space-separated list to `genkey` and join required attributes with `&&`
in the encryption policy. Setup creates the authority's master
secret key (`cpabe_msk.key`) and public key (`cpabe_pk.key`). Use the master
secret key to issue user keys, and share the public key with encryptors.

To add ML-DSA-87 signing and verification to the same post-quantum ABE flow,
use a separate key directory and the same `message.txt`.

```sh
mkdir signed-keys
python -m pq_cp_abe setup-pqc signed-keys
python -m pq_cp_abe genkey signed-keys/cpabe_msk.key "role::admin department::finance" signed-keys/user.key
python -m pq_cp_abe encrypt-pqc signed-keys/cpabe_pk.key signed-keys/pqc_sk.key message.txt "role::admin && department::finance" signed.enc
python -m pq_cp_abe decrypt-pqc signed-keys/user.key signed-keys/pqc_pk.key signed.enc verified.txt
```

### Run a post-quantum ABE example in Python

Copy this into `demo.py` and run `python demo.py`. It creates an authority,
issues a user key with `role::admin` and `department::finance`, and encrypts
and decrypts a message in memory using CoverCrypt in hybridized mode.
It also checks that a user key from the engineering department cannot
decrypt the same ciphertext.
Each step reports `OK` or `FAILED`. A failure prints the error and exits with
status 1.

```python
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

import pq_cp_abe as abe


@contextmanager
def step(number, label):
    prefix = f"[{number}/7] {label}"
    print(f"{prefix} ...", flush=True)
    try:
        yield
    except Exception as error:
        print(f"{prefix}: FAILED ({error})", file=sys.stderr, flush=True)
        raise SystemExit(1) from None
    print(f"{prefix}: OK", flush=True)


def main():
    mode = "hybridized"
    attributes = "role::admin department::finance"
    policy = "role::admin && department::finance"
    message = b"Hello from PQ-CP-ABE"

    print(f"Native library version: {abe.get_version()}")
    print(f"Scheme: CoverCrypt ({mode})")

    with TemporaryDirectory() as directory:
        with step(1, "Write the CoverCrypt configuration"):
            config = Path(directory) / "attributes-dimensions.json"
            config.write_text(json.dumps({"dimensions": [
                {"name": "role", "attributes": ["admin", "analyst"]},
                {"name": "department", "attributes": ["finance", "engineering"]},
            ]}), encoding="utf-8")
            os.environ["HCPABE_COVERCRYPT_CONFIG"] = str(config)
            os.environ["HCPABE_COVERCRYPT_MODE"] = mode

        with step(2, "Create authority keys"):
            public_key, master_key = abe.setup_buffer()

        with step(3, f"Issue a user key for {attributes}"):
            user_key = abe.genkey_buffer(master_key, attributes)

        with step(4, f"Encrypt under policy {policy}"):
            ciphertext = abe.call_hybrid_cpabe_encryptBuffer(public_key, message, policy)
            print(f"    Ciphertext size: {len(ciphertext)} bytes")

        with step(5, "Decrypt with the user key"):
            recovered = abe.call_hybrid_cpabe_decryptBuffer(user_key, ciphertext)

        with step(6, "Compare the recovered message with the original"):
            if recovered != message:
                raise ValueError("The decrypted message does not match the original")
            print(f"    Recovered message: {recovered.decode('utf-8')}")

        with step(7, "Check that a user from engineering is denied"):
            other_attributes = "role::admin department::engineering"
            other_key = abe.genkey_buffer(master_key, other_attributes)
            try:
                abe.call_hybrid_cpabe_decryptBuffer(other_key, ciphertext)
            except RuntimeError as error:
                if "Attributes do not satisfy policy" not in str(error):
                    raise
                print(f"    Access denied as expected for {other_attributes}")
            else:
                raise RuntimeError("The engineering user unexpectedly decrypted the message")


if __name__ == "__main__":
    main()
```

For existing AC17 or TKN20 keys, pass `scheme=abe.CPABE_SCHEME_AC17` or
`scheme=abe.CPABE_SCHEME_TKN20` to setup, key generation and encryption.
Decryption detects the scheme from the ciphertext.
See the [scheme guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/architecture.md#native-pqc-with-covercrypt).

### Choose hybrid or PQC-only key encapsulation

CoverCrypt supports three modes for protecting the secret behind the access
policy. Choose one with `HCPABE_COVERCRYPT_MODE` before setup.

| Mode | CoverCrypt key encapsulation |
| --- | --- |
| `hybridized` (default) | Combines a classical Curve25519-based shared secret and an ML-KEM-768 shared secret in the same encapsulation. Decapsulation uses both components. |
| `post_quantum` | Uses ML-KEM-768 alone for key encapsulation. |
| `classic` | Uses the classical Curve25519-based component alone. |

For a **PQC-only ABE/KEM demo**, select `post_quantum` and run setup in a
fresh key directory. Keep `HCPABE_COVERCRYPT_CONFIG` set to the dimensions file
from the CLI example above.

- Bash: `export HCPABE_COVERCRYPT_MODE=post_quantum`
- PowerShell: `$env:HCPABE_COVERCRYPT_MODE = 'post_quantum'`
- CMD: `set "HCPABE_COVERCRYPT_MODE=post_quantum"`

In `demo.py`, change the mode to `"post_quantum"` before calling
`abe.setup_buffer()`. Setup applies the selected mode to the configured
attributes. Encryption uses the mode encoded in the public key for the
selected rights. To switch modes for an existing demo, generate a new authority
and issue new user keys. Changing the environment variable alone leaves
existing keys and ciphertext unchanged.

All three modes use AES-256-GCM for payload encryption. ML-DSA-87 is a
separate, optional signature layer. See the
[C++ mode selector](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/src/schemes/covercrypt.cpp) and the
[CoverCrypt encapsulation implementation](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/vendor/cover_crypt/src/abe/core/primitives.rs).

## Layout

`pq_cp_abe/_native.py` handles `ctypes` loading and the C ABI, `api.py` exposes the existing Python API, `__main__.py` implements the CLI, and `_libs/` holds the bundled native runtimes.

## Native GitHub Release as the binary source

The standard path in `.github/workflows/publish-pypi.yml` uses *already published* native ZIPs from the exact `v<VERSION>` GitHub Release. `stage_native.py` verifies the archive against the release's `SHA256SUMS.txt` and stages the runtime binaries and license files.

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

To prepare the Monterey SDKs and wheels for `6.0.2`, run **Build Python Wheels**
with `macos12_backfill=true` and `publish=false`. The workflow builds from tag
`v6.0.2` with deployment target `12.0` and produces a native ZIP and a wheel for
each architecture.

On matching Intel and Apple Silicon systems running macOS 12, extract each
native ZIP and run `bin/main version`, then install its wheel and run
`python -m pq_cp_abe --test`. With `publish=true`, the same mode adds
`libhybrid-pq-cp-abe_macos12_<arch>_v6.0.2.zip` and `SHA256SUMS-macos12.txt`
to the GitHub Release and publishes the two `macosx_12_0` wheels to PyPI.

From GitHub Actions, run **Build Python Wheels** with the `publish` input set to `false` to build/test/download the wheel artifacts only.

Once all four jobs pass, configure a PyPI *Trusted Publisher* for this GitHub repository, workflow `publish-pypi.yml`, and environment `pypi`. Then manually dispatch the workflow with `publish=true`. This is opt-in: no deployment occurs on ordinary pushes or releases.

The existing native `release.yml` is unchanged and Python publishing is independent. Source distribution (`sdist`) is intentionally not published because it cannot install a functioning native runtime by itself.

For local source development, the SDK can still fall back to the repository's `lib/` binaries when available. This is separate from GitHub Release staging for wheels.

Compatibility entrypoints `bindings/python/hybrid_pq_cp_abe.py` and `bindings/python/test_api.py` remain, while new callers should use `pq_cp_abe`.
