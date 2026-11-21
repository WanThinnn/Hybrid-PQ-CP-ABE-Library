# PQ-CP-ABE for Python

Python SDK for native Ciphertext-Policy Attribute-Based Encryption (CP-ABE) with post-quantum cryptography support. It combines AC17, TKN20, or CoverCrypt with AES-GCM and optional ML-DSA digital signatures. CoverCrypt supports ML-KEM-768 for key encapsulation, while AC17 and TKN20 use classical ABE.


```sh
python -m pip install pq-cp-abe
```

**Full documentation:** [Python SDK guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/python/README.md) · [API reference](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/python/api.md) · [CLI guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/python/cli.md) · [Automatic API docs](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/python/api-generation.md).

## Object API

`PqCpAbe` defaults to CoverCrypt. Pass `scheme` to select another backend.
This example encrypts a message for finance users and verifies an ML-DSA
signature on decryption.

```python
from pq_cp_abe import KemMode, MlDsaParameterSet, PqCpAbe

abe = PqCpAbe(
    config={"dimensions": [{"name": "department", "attributes": ["finance", "it"]}]},
    mode=KemMode.HYBRIDIZED,
)
parameter = MlDsaParameterSet.ML_DSA_65
keys = abe.setup_with_signing(ml_dsa_parameter_set=parameter)
user_key = abe.keygen(keys.master_secret_key, "department::finance")

ciphertext = abe.encrypt_and_sign(
    keys.public_key, keys.signing_key, b"Quarterly report", "department::finance",
    aes_key_bits=192, ml_dsa_parameter_set=parameter,
)
plaintext = abe.decrypt_and_verify(user_key, keys.verification_key, ciphertext)
assert plaintext == b"Quarterly report"
```

Use `setup()`, `encrypt()`, and `decrypt()` for unsigned data. Encryption
accepts AES 128/192/256. Signed setup and encryption accept ML-DSA 44/65/87.
Omitting both parameters uses AES-256 and, when signing, ML-DSA-87.

| Class | Use |
| --- | --- |
| `AC17CPABE`, `TKN20CPABE` | Use a specific classical ABE scheme. |
| `CoverCryptABE` | Configure dimensions and `KemMode`. Use `add_dimension` or `add_attribute` to grow an authority and save both updated keys. |
| `AesGcm` | Generate a key and a fresh nonce, then encrypt or decrypt bytes. |
| `MlDsa`, `MlKem` | Sign and verify with raw keys, or encapsulate and decapsulate a shared secret. `get_sizes()` reports sizes for the selected parameter set. |

CoverCrypt supports `KemMode.HYBRIDIZED`, `POST_QUANTUM`, and `CLASSIC`. Its
post-quantum component uses ML-KEM-768. Standalone `MlKem` supports 512/768/1024.
When adding an attribute, the native runtime reads the mode from
`HCPABE_COVERCRYPT_MODE`.

## Functional API

Use package-level functions when passing the scheme per operation or working
with files. Native failures raise `AbeError` and its subclasses.

```python
from pq_cp_abe import Scheme, generate_secret_key, setup

keys = setup(scheme=Scheme.AC17)
user_key = generate_secret_key(keys.master_secret_key, "admin", scheme=Scheme.AC17)
```

File operations include `setup_files`, `generate_secret_key_file`,
`encrypt_file`, and `decrypt_file`. For signed setup, use
`setup_files_with_signing(..., legacy_key_names=False)` to generate the
`ml-dsa_sk.key` and `ml-dsa_pk.key` filenames. `call_*` remains available
for existing integrations.

## Post-quantum ABE from the CLI

Use `python -m pq_cp_abe` to select the Python CLI if multiple installations
provide `pq-cp-abe`. The `--setup` command accepts `--config` or the
`HCPABE_COVERCRYPT_CONFIG` environment variable.

```sh
pq-cp-abe --help
pq-cp-abe --encrypt --help
python -m pq_cp_abe --test
```

The full CLI workflow covers setup, user key generation, signed encryption,
and verification. [CoverCrypt CLI example](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/native/cli.md#covercrypt-with-ml-dsa-signatures)

Platform wheels bundle the native library. For staging, building, and
verifying wheels, see the [Python wheel workflow](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/.github/workflows/publish-pypi.yml).
