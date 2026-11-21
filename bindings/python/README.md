# PQ-CP-ABE Python SDK

A Native Post-Quantum Ciphertext-Policy Attribute-Based Encryption SDK for Python. It combines
AC17, TKN20, or CoverCrypt with AES-GCM and optional ML-DSA signatures. CoverCrypt
supports ML-KEM-768 for key encapsulation. AC17 and TKN20 use classical ABE.

[Latest release](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/latest) · [Release notes](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/release_notes)

## Quick start

Install the package on Python 3.10 or later once the wheel is published to PyPI.
You can also install the wheel for your platform directly from GitHub Releases
with `python -m pip install <downloaded-wheel.whl>`.

```sh
python -m pip install pq-cp-abe
```

## Native API

Use the functions directly for in-memory operations or file-based workflows.
This example configures CoverCrypt with JSON.

```python
import json
import pq_cp_abe as abe

config = json.dumps({"dimensions": [
    {"name": "role", "attributes": ["admin", "analyst"]},
    {"name": "department", "attributes": ["finance", "engineering"]},
]})
keys = abe.covercrypt_setup(config, mode=abe.KemMode.HYBRIDIZED)
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
The standalone `MlDsa` class uses raw key bytes.
File operations accept `str` or `PathLike[str]` and return `None` on success;
setup retains native directory/prefix naming. The new wrappers add no console
output, although native file functions may still write logs.

New API native failures raise `AbeError` with `.code` and `.operation`;
native codes -3 and -9 map to `PolicyMismatchError` and `SignatureInvalidError`.
Other native failures remain `AbeError`, including -4 for a generic
cryptographic failure. Invalid Python inputs raise `TypeError`/`ValueError`.
The package ships annotations and a `py.typed` marker.

The functional and object APIs share the same implementation. Raw key bytes
remain application-owned; Python does not guarantee secure erasure of immutable bytes.

Encrypt data under a policy such as `role::admin && department::finance`.
Only a user whose key grants the admin role in the finance department can
decrypt it. This is
**ciphertext-policy attribute-based encryption (CP-ABE)**.

The default scheme, **CoverCrypt**, brings **post-quantum protection to ABE
key encapsulation**. Its default `hybridized` mode combines Curve25519 and
ML-KEM-768 to protect the secret used for AES-GCM payload encryption.
Optional ML-DSA signatures authenticate the signed data.
AC17 and TKN20 use classical ABE key protection, including when signing
is enabled.

- PyPI distribution: `pq-cp-abe`
- Import: `import pq_cp_abe`
- The repository root `VERSION` is the sole build version; installed packages read the embedded distribution metadata.
- Version 6.1 declares `ctypes` signatures for all 52 public C exports.
- Run `python -m pq_cp_abe --test` for the bundled compatibility self-test.
  The repository suite covers the 6.1 parameters, classes, CLI, and public exports.


## Object API

`PqCpAbe` delegates to `AC17CPABE`, `TKN20CPABE`, or `CoverCryptABE` through
the `BaseCPABE` interface. Objects keep configuration rather than secret keys.
The OOP API operates on bytes; existing file operations remain in the functional API.

```python
from pq_cp_abe import PqCpAbe, KemMode

abe = PqCpAbe(config={"dimensions": [
    {"name": "role", "attributes": ["admin", "analyst"]},
    {"name": "department", "attributes": ["finance", "engineering"]},
]}, mode=KemMode.HYBRIDIZED)
keys = abe.setup()
secret_key = abe.keygen(keys.master_secret_key, "role::admin department::finance")
ciphertext = abe.encrypt(keys.public_key, b"Hello", "role::admin && department::finance")
assert abe.decrypt(secret_key, ciphertext) == b"Hello"
```

Use `PqCpAbe(scheme=Scheme.AC17)`, `AC17CPABE()`, or `TKN20CPABE()` for the
classical backends. `keygen` and `generate_secret_key` are equivalent. All
objects also offer `setup_with_signing`, `encrypt_and_sign`, and
`decrypt_and_verify`. Set `aes_key_bits` to 128, 192, or 256 when encrypting.
For signed encryption, pass the same `ml_dsa_parameter_set` (44, 65, or 87)
to setup and encryption. Omitting both parameters uses AES-256 and ML-DSA-87
with the legacy ciphertext format.

Standalone primitives select their own parameters.

```python
from pq_cp_abe import AesGcm, MlDsa, MlKem, MlDsaParameterSet, MlKemParameterSet

aes = AesGcm(key_size_bits=192)
key, nonce = aes.generate_key(), aes.generate_nonce()
ciphertext = aes.encrypt(key, nonce, b"payload", aad=b"context")
assert aes.decrypt(key, nonce, ciphertext, aad=b"context") == b"payload"

signer = MlDsa(parameter_set=MlDsaParameterSet.ML_DSA_65)
signing_keys = signer.generate_keypair()
signature = signer.sign(b"payload", signing_keys.secret_key)
assert signer.verify(b"payload", signature, signing_keys.public_key)

kem = MlKem(parameter_set=MlKemParameterSet.ML_KEM_1024)
kem_keys = kem.generate_keypair()
sealed = kem.encapsulate(kem_keys.public_key)
assert kem.decapsulate(kem_keys.secret_key, sealed.ciphertext) == sealed.shared_secret
```

Use a new nonce for each AES-GCM encryption with a given key. ML-KEM implicit
rejection can yield a different secret for a modified ciphertext without an
error. Authenticate encrypted payloads. Use `get_sizes()` on `MlDsa` or
`MlKem` to query sizes for the selected parameter set. ML-DSA verification
returns `False` for an invalid signature. Operational errors raise exceptions.

CoverCrypt snapshots its configuration on construction (including the config
file from `HCPABE_COVERCRYPT_CONFIG` when no explicit config is given). Its
mode is instance-local: `CLASSIC`, `POST_QUANTUM`, or `HYBRIDIZED`. This build's
CoverCrypt provider uses ML-KEM-768, independently of the standalone `MlKem`
class, which supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

Canonical module layout:

| Module | Responsibility |
| --- | --- |
| `_native.py` | C ABI declarations and shared-library loading |
| `api/legacy.py` | Historical `call_*` and helper behavior |
| `api/functional.py` | Modern functions, native buffer ownership and error handling |
| `abe/`, `pq_cp_abe.py` | Scheme objects and `PqCpAbe` facade |
| `primitives/` | `AesGcm`, `MlDsa`, `MlKem` objects |
| `models/`, `utils/` | Shared results, enums, validation and errors |

Import classes and functions from `pq_cp_abe`. Historical `call_*` functions
and buffer helpers remain available through their original imports and
`pq_cp_abe.api.legacy` for compatibility.


### Python CLI

Run `pq-cp-abe --help` after installing the wheel. Use
`python -m pq_cp_abe --help` to select the Python CLI explicitly when several
installations provide `pq-cp-abe`. The demo uses CoverCrypt in its default
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
pq-cp-abe --setup --scheme covercrypt --file keys
pq-cp-abe --genkey --scheme covercrypt --master-key keys/cpabe_msk.key --attributes "role::admin department::finance" --user-key keys/user.key
pq-cp-abe --encrypt --scheme covercrypt --public-key keys/cpabe_pk.key --file message.txt --policy "role::admin && department::finance" --ciphertext message.enc
pq-cp-abe --decrypt --user-key keys/user.key --ciphertext message.enc --output recovered.txt
python -c "from pathlib import Path; print(Path('recovered.txt').read_text(encoding='utf-8'))"
```

CoverCrypt writes each attribute as `dimension::value`. Pass a
space-separated list to `genkey` and join required attributes with `&&`
in the encryption policy. Setup creates the authority's master
secret key (`cpabe_msk.key`) and public key (`cpabe_pk.key`). Use the master
secret key to issue user keys, and share the public key with encryptors.

To add ML-DSA signing and verification, use a separate key prefix and the
same `message.txt`.

```sh
pq-cp-abe --setup --scheme covercrypt --file signed --with-signing-keys --ml-dsa 65
pq-cp-abe --genkey --scheme covercrypt --master-key signed_msk.key --attributes "role::admin department::finance" --user-key user.key
pq-cp-abe --encrypt --scheme covercrypt --sign --public-key signed_pk.key --signing-key signed_ml-dsa_sk.key --file message.txt --policy "role::admin && department::finance" --ciphertext signed.enc --aes-bits 192 --ml-dsa 65
pq-cp-abe --decrypt --verify --user-key user.key --verification-key signed_ml-dsa_pk.key --ciphertext signed.enc --output verified.txt
```

The signed example uses AES-192 and ML-DSA-65. Omitting the parameter flags
uses AES-256 and ML-DSA-87. The original `*-pqc` commands support existing scripts.

For the functional API and CP-ABE classes, use `aes_key_bits` with `encrypt`
or `encrypt_and_sign`, and `ml_dsa_parameter_set` with `setup_with_signing`
and `encrypt_and_sign`. File operations accept the same keyword arguments.
Pass `legacy_key_names=False` to `setup_files_with_signing` for the
`ml-dsa_sk.key` and `ml-dsa_pk.key` names. Decryption detects the ciphertext
format and parameters. `CoverCryptABE.add_dimension` uses the instance's mode.
`add_attribute` uses the native CoverCrypt mode from the environment. Retain
both keys returned by either operation.

### Sign and encrypt with CoverCryptABE

Save this as `demo.py` and run `python demo.py`. It verifies the signature and
checks that a key with the wrong department is denied.

```python
from pq_cp_abe import CoverCryptABE, KemMode, MlDsaParameterSet, PolicyMismatchError

authority = CoverCryptABE(
    config={"dimensions": [
        {"name": "role", "attributes": ["admin", "analyst"]},
        {"name": "department", "attributes": ["finance", "engineering"]},
    ]},
    mode=KemMode.HYBRIDIZED,
)
parameter = MlDsaParameterSet.ML_DSA_65
keys = authority.setup_with_signing(ml_dsa_parameter_set=parameter)
user_key = authority.keygen(keys.master_secret_key, "role::admin department::finance")
message = b"Hello from PQ-CP-ABE"
ciphertext = authority.encrypt_and_sign(
    keys.public_key, keys.signing_key, message,
    "role::admin && department::finance",
    aes_key_bits=192, ml_dsa_parameter_set=parameter,
)
recovered = authority.decrypt_and_verify(user_key, keys.verification_key, ciphertext)
assert recovered == message

other_key = authority.keygen(keys.master_secret_key, "role::admin department::engineering")
try:
    authority.decrypt_and_verify(other_key, keys.verification_key, ciphertext)
except PolicyMismatchError:
    print("Engineering access denied")
else:
    raise AssertionError("An engineering key decrypted the finance message")
```

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

In `demo.py`, pass `mode=KemMode.POST_QUANTUM` to `CoverCryptABE` before
creating the authority. Encryption uses the mode encoded in the public key
for the selected rights. To switch modes for the demo, generate a new
authority and issue new user keys.

All three modes support AES-GCM payload encryption. The optional ML-DSA
signature layer has its own parameter set. See the
[C++ mode selector](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/src/schemes/covercrypt.cpp) and the
[CoverCrypt encapsulation implementation](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/vendor/cover_crypt/src/abe/core/primitives.rs).

## Layout

`pq_cp_abe/_native.py` loads the C ABI with `ctypes`. `api/` contains the functional API and legacy wrappers, `__main__.py` implements the CLI, and `_libs/` holds the bundled native runtimes.

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

From GitHub Actions, run **Build Python Wheels** with the `publish` input set to `false` to build/test/download the wheel artifacts only.

Once all four jobs pass, configure a PyPI *Trusted Publisher* for this GitHub repository, workflow `publish-pypi.yml`, and environment `pypi`. Then manually dispatch the workflow with `publish=true`. This is opt-in: no deployment occurs on ordinary pushes or releases.

The existing native `release.yml` is unchanged and Python publishing is independent. Source distribution (`sdist`) is intentionally not published because it cannot install a functioning native runtime by itself.

For local source development, the SDK can still fall back to the repository's `lib/` binaries when available. This is separate from GitHub Release staging for wheels.

The `macos12_backfill` workflow input rebuilds the Monterey artifacts for
version 6.0.2. [Version 6.0.2 release notes](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/release_notes/v6.0.2.md)
