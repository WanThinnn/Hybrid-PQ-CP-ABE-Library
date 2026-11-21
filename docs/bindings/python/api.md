# Python SDK — API reference

This is a curated reference to the **implemented v6.1-style API**, not automatically generated from docstrings. For the original implementation see [`bindings/python/pq_cp_abe/`](../../../bindings/python/pq_cp_abe/) and [Python type annotations](../../../bindings/python/pq_cp_abe/api/functional.py).

## Imports and layout

~~~python
from pq_cp_abe import (
    PqCpAbe, BaseCPABE, AC17CPABE, TKN20CPABE, CoverCryptABE,
    Scheme, KemMode, MlDsaParameterSet, MlKemParameterSet,
    AesGcm, MlDsa, MlKem,
    AbeError, PolicyMismatchError, SignatureInvalidError,
)
~~~

- `pq_cp_abe.abe`: object wrappers for ABE backends.
- `pq_cp_abe.api.functional`: public functional/buffer + file API, re-exported at package root.
- `pq_cp_abe.primitives`: standalone AES-GCM, ML-DSA, ML-KEM objects.
- `pq_cp_abe.models`: enums and immutable typed result tuples.
- `pq_cp_abe.api.legacy` and package `call_*` functions: compatibility wrappers; prefer the modern layer for new code.
- `pq_cp_abe.native`: low-level `ctypes.CDLL`; only for integrations that intentionally manage C ABI parameters.

### Enumerations

| Name | Members |
| --- | --- |
| `Scheme` | `AC17`, `TKN20`, `COVERCRYPT` |
| `KemMode` | `CLASSIC`, `POST_QUANTUM`, `HYBRIDIZED` |
| `MlDsaParameterSet` | `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87` |
| `MlKemParameterSet` | `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024` |

## Object interface

### `PqCpAbe`, `AC17CPABE`, `TKN20CPABE`, `CoverCryptABE`

~~~python
abe = PqCpAbe(
    scheme=Scheme.COVERCRYPT,
    config={"dimensions": [{"name": "team", "attributes": ["blue", "red"]}]},
    mode=KemMode.HYBRIDIZED,
)
~~~

For classical schemes, instantiate `AC17CPABE()`, `TKN20CPABE()`, or `PqCpAbe(scheme=Scheme.AC17)`. `config`, `mode` and `parameter_set` are meaningful only for CoverCrypt.

| Method | Inputs | Result |
| --- | --- | --- |
| `setup()` | none | `AuthorityKeys(public_key, master_secret_key)` |
| `keygen(master_secret_key, attributes)` | `bytes`, `str` | user secret key `bytes` |
| `generate_secret_key(...)` | alias for `keygen` | `bytes` |
| `encrypt(public_key, plaintext, policy, *, aes_key_bits=None)` | `bytes`, `bytes`, `str` | ciphertext `bytes` |
| `decrypt(secret_key, ciphertext)` | `bytes`, `bytes` | plaintext `bytes` |
| `setup_with_signing(*, ml_dsa_parameter_set=None)` | optional parameter set | `AuthoritySigningKeys` |
| `encrypt_and_sign(public_key, signing_key, plaintext, policy, *, aes_key_bits=None, ml_dsa_parameter_set=None)` | signing key in combined format | signed ciphertext `bytes` |
| `decrypt_and_verify(secret_key, verification_key, ciphertext)` | keys in combined format | verified plaintext `bytes` |

`PqCpAbe.backend` identifies the selected scheme adapter; `scheme` is read-only.

`CoverCryptABE` additionally provides:

| Method | Behavior |
| --- | --- |
| `add_dimension(master_secret_key, dimension_json)` | Add a dimension JSON definition and return updated `AuthorityKeys` |
| `add_attribute(master_secret_key, dimension, attribute, *, after=None)` | Add one attribute and return updated `AuthorityKeys` |
| `mode` / `parameter_set` | Read configured KEM mode; this build's CoverCrypt KEM parameter set is ML-KEM-768 |

The attribute method uses the native environment mode for the newly added attribute; see [architecture notes](../../architecture.md). Persist **both** updated authority keys. Growth is not equivalent to revocation.

### Result types

| Type | Fields |
| --- | --- |
| `AuthorityKeys` | `public_key: bytes`, `master_secret_key: bytes` |
| `AuthoritySigningKeys` | above + `verification_key: bytes`, `signing_key: bytes` |
| `KeyPair` | `public_key: bytes`, `secret_key: bytes` |
| `KemEncapsulation` | `ciphertext: bytes`, `shared_secret: bytes` |

## Functional operations

Import via `from pq_cp_abe import setup, encrypt, ...` or `from pq_cp_abe.api import functional as api`.

**In-memory ABE**

| Function | Key arguments | Return |
| --- | --- | --- |
| `setup(*, scheme=Scheme.COVERCRYPT)` | scheme | `AuthorityKeys` |
| `covercrypt_setup(config_json, *, mode=KemMode.HYBRIDIZED)` | JSON string | `AuthorityKeys` |
| `setup_with_signing(*, scheme=..., ml_dsa_parameter_set=None)` | scheme, signing set | `AuthoritySigningKeys` |
| `generate_secret_key(master_secret_key, attributes, *, scheme=...)` | `bytes`, `str` | `bytes` |
| `encrypt(public_key, plaintext, policy, *, scheme=..., aes_key_bits=None)` | key/bytes/policy | `bytes` |
| `decrypt(secret_key, ciphertext)` | key/ciphertext | `bytes` |
| `encrypt_and_sign(public_key, signing_key, plaintext, policy, *, scheme=..., aes_key_bits=None, ml_dsa_parameter_set=None)` | signing key and policy | `bytes` |
| `decrypt_and_verify(secret_key, verification_key, ciphertext)` | verification key | `bytes` |
| `covercrypt_add_dimension_with_mode(master_secret_key, dimension_json, *, mode=...)` | authority + JSON | `AuthorityKeys` |
| `covercrypt_ml_kem_parameter_set()` | none | `MlKemParameterSet.ML_KEM_768` |

Plain `setup(scheme=Scheme.COVERCRYPT)` reads the native environment configuration; use `covercrypt_setup(config_json, mode=...)` to supply explicit JSON without mutating the environment.

**Native file operations**

| Function | Key arguments | Return |
| --- | --- | --- |
| `setup_files(output_path, *, scheme=...)` | directory or prefix | `None` |
| `setup_files_with_signing(output_path, *, scheme=..., ml_dsa_parameter_set=None, legacy_key_names=True)` | output naming | `None` |
| `generate_secret_key_file(master_secret_key_path, attributes, output_path, *, scheme=...)` | input/output paths | `None` |
| `encrypt_file(public_key_path, plaintext_path, policy, output_path, *, scheme=..., aes_key_bits=None)` | file paths | `None` |
| `decrypt_file(secret_key_path, ciphertext_path, output_path)` | file paths | `None` |
| `encrypt_and_sign_file(public_key_path, signing_key_path, plaintext_path, policy, output_path, *, scheme=..., aes_key_bits=None, ml_dsa_parameter_set=None)` | paths | `None` |
| `decrypt_and_verify_file(secret_key_path, verification_key_path, ciphertext_path, output_path)` | paths | `None` |

File functions use **real OS paths**, unlike WASM file APIs. For naming and CLI examples, see [Python CLI](cli.md).

## Standalone cryptographic primitives

These APIs use **raw keys** and are distinct from the combined ABE signing-key representation.

| Object | Constructor | Methods |
| --- | --- | --- |
| `AesGcm` | `AesGcm(key_size_bits=256)` | `generate_key()`, `generate_nonce()`, `encrypt(key, nonce, plaintext, aad=b"")`, `decrypt(...)` |
| `MlDsa` | `MlDsa(parameter_set=MlDsaParameterSet.ML_DSA_87)` | `generate_keypair()`, `get_sizes()`, `sign(message, secret_key)`, `verify(message, signature, public_key)` |
| `MlKem` | `MlKem(parameter_set=MlKemParameterSet.ML_KEM_768)` | `generate_keypair()`, `get_sizes()`, `encapsulate(public_key)`, `decapsulate(secret_key, ciphertext)` |

~~~python
from pq_cp_abe import AesGcm, MlDsa, MlKem

aes = AesGcm(256)
key, nonce = aes.generate_key(), aes.generate_nonce()
ciphertext = aes.encrypt(key, nonce, b"record", aad=b"context")
assert aes.decrypt(key, nonce, ciphertext, aad=b"context") == b"record"

signer = MlDsa()
pair = signer.generate_keypair()
signature = signer.sign(b"record", pair.secret_key)
assert signer.verify(b"record", signature, pair.public_key)

kem = MlKem()
recipient = kem.generate_keypair()
enc = kem.encapsulate(recipient.public_key)
assert kem.decapsulate(recipient.secret_key, enc.ciphertext) == enc.shared_secret
~~~

For AES-GCM, never reuse the same nonce with a key. ML-KEM decapsulation alone does **not** authenticate the sender or ciphertext.

Functional equivalents: `aes_gcm_generate_key/encrypt/decrypt`, `ml_dsa_generate_keypair/get_sizes/sign/verify`, `ml_kem_generate_keypair/get_sizes/encapsulate/decapsulate`. Function arguments are documented in [`functional.py`](../../../bindings/python/pq_cp_abe/api/functional.py).

## Errors and compatibility

- Modern native failures raise `AbeError(code, operation)`; `PolicyMismatchError` and `SignatureInvalidError` specialize native error codes -3 and -9.
- Bad Python arguments can raise `TypeError` or `ValueError`; an unsupported modern native export can raise `NotImplementedError` when loading older binaries.
- A standalone `MlDsa.verify` returns `False` for an invalid signature rather than returning plaintext.
- Explicit AES/signing parameters change the hybrid wire format to V3; decryption detects ciphertext parameters automatically. See [native parameters](../../native_parameters.md).
- Legacy `call_*` names remain available. They retain historical return-code/data semantics and are not interchangeable with the typed modern errors.
