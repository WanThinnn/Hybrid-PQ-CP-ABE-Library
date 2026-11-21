# Python SDK — guide

The `pq-cp-abe` Python package exposes the project's native C ABI using `ctypes`. It **does not run WebAssembly**. On supported operating systems, a compatible platform wheel includes the native runtime.

## Contents

- [API reference](api.md) — object/functional methods, parameters, return types, exceptions and standalone cryptographic primitives.
- [Python CLI and file operations](cli.md) — named flags, signed workflows, CoverCrypt configuration and file naming.
- [Automatic API documentation](api-generation.md) — generate class/function docs from type annotations and docstrings.
- [Native format and parameters](../../native_parameters.md) · [Architecture and access policies](../../architecture.md) · [Building from source](../../build.md).

## Install

Requires Python 3.10 or newer and a wheel compatible with the current OS/CPU.

~~~sh
python -m pip install pq-cp-abe
python -c "import pq_cp_abe as abe; print(abe.__version__, abe.get_version())"
~~~

To work against the local Python source in this repository (ideally inside a virtual environment):

~~~sh
python -m pip install -e ./bindings/python
python -c "import pq_cp_abe; print(pq_cp_abe.__file__)"
~~~

An editable installation updates Python code as you edit it. **It does not rebuild native libraries.** In source checkouts, `pq_cp_abe/_native.py` first looks for packaged `pq_cp_abe/_libs/`, then the repository's `lib/` fallback. If you rebuild a native binary, verify which library the Python process loads. On Windows, `libcpabe_tkn20.dll` must accompany the main DLL.

## Quick start — CoverCrypt with in-memory keys

~~~python
from pq_cp_abe import KemMode, PqCpAbe

abe = PqCpAbe(
    config={
        "dimensions": [
            {"name": "department", "attributes": ["finance", "it"]},
        ]
    },
    mode=KemMode.HYBRIDIZED,
)
keys = abe.setup()
user_key = abe.keygen(keys.master_secret_key, "department::finance")
encrypted = abe.encrypt(keys.public_key, b"Confidential report", "department::finance")
assert abe.decrypt(user_key, encrypted) == b"Confidential report"
~~~

The object defaults to `Scheme.COVERCRYPT` and `KemMode.HYBRIDIZED`. When using CoverCrypt, supply a dimensions JSON object or set `HCPABE_COVERCRYPT_CONFIG` to an existing JSON file before constructing the object. The object snapshots configuration at construction.

## Signed encryption — ML-DSA

~~~python
from pq_cp_abe import KemMode, MlDsaParameterSet, PqCpAbe

abe = PqCpAbe(
    config={"dimensions": [{"name": "role", "attributes": ["admin", "viewer"]}]},
    mode=KemMode.POST_QUANTUM,
)
parameter = MlDsaParameterSet.ML_DSA_65
keys = abe.setup_with_signing(ml_dsa_parameter_set=parameter)
user_key = abe.keygen(keys.master_secret_key, "role::admin")

ciphertext = abe.encrypt_and_sign(
    keys.public_key, keys.signing_key, b"Signed document", "role::admin",
    aes_key_bits=192, ml_dsa_parameter_set=parameter,
)
plaintext = abe.decrypt_and_verify(user_key, keys.verification_key, ciphertext)
assert plaintext == b"Signed document"
~~~

`setup_with_signing()` generates an **additional** signing/verification keypair; it does not sign the generated ABE keys. Use `decrypt_and_verify` to obtain verified plaintext. Plain `decrypt` is **not** a substitute for signature verification on signed ciphertext.

## Other ABE schemes

~~~python
from pq_cp_abe import AC17CPABE, TKN20CPABE, PqCpAbe, Scheme

ac17 = AC17CPABE()
tkn20 = TKN20CPABE()
facade = PqCpAbe(scheme=Scheme.AC17)
keys = facade.setup()
user = facade.keygen(keys.master_secret_key, "admin it")
ciphertext = facade.encrypt(keys.public_key, b"hello", "admin and it")
assert facade.decrypt(user, ciphertext) == b"hello"
~~~

Keys and policies are scheme-specific. Decryption derives the scheme from the ciphertext; **keys are not interchangeable across schemes**. AC17/TKN20 remain classical ABE even if ML-DSA signatures are enabled.

## Parameter choices

| Property | Choices | Default |
| --- | --- | --- |
| Hybrid AES-GCM size | 128 / 192 / 256 bits | AES-256 |
| Optional signing | ML-DSA-44 / 65 / 87 | ML-DSA-87 |
| CoverCrypt KEM mode | `CLASSIC` / `POST_QUANTUM` / `HYBRIDIZED` | `HYBRIDIZED` |
| ML-KEM inside CoverCrypt | 768 | Fixed at 768 |
| Standalone `MlKem` | 512 / 768 / 1024 | 768 |

Passing explicit `aes_key_bits` or `ml_dsa_parameter_set` in encryption selects the newer V3 ciphertext format. Omitted parameters preserve the legacy-compatible encryption path; read [native parameter documentation](../../native_parameters.md) before exchanging ciphertext with older runtimes.

## Security and key handling

- Store the master secret key and ML-DSA signing key securely; distribute the public and verification keys through an authenticated channel.
- Combined ABE `AuthoritySigningKeys.signing_key` and `verification_key` are **Base64-encoded bytes** in the native setup format. Standalone `MlDsa.generate_keypair()` returns **raw** ML-DSA key bytes. Do not mix formats.
- Authority growth via `CoverCryptABE.add_dimension` / `add_attribute` returns an updated **public key and master secret key**. Persist both; old issued rights are not revoked automatically.
- In-memory `keygen` is stateless with respect to persistent authority metadata. Consult [architecture notes](../../architecture.md) about CoverCrypt issuance/tracing and concurrent file updates.
- Exceptions in the modern Python API include `AbeError`, `PolicyMismatchError` and `SignatureInvalidError`. Do not expose failed-decryption output.
