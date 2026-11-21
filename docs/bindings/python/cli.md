---
icon: lucide/terminal
---

# CLI and file workflows

The Python wheel installs a `pq-cp-abe` console script. When both the native CLI and Python wheel are installed, invoke `python -m pq_cp_abe` to **explicitly choose the Python implementation**.

~~~sh
python -m pq_cp_abe --help
python -m pq_cp_abe encrypt --help
python -m pq_cp_abe --version
python -m pq_cp_abe --test
~~~

Commands include `setup`, `genkey`, `encrypt`, `decrypt`, buffer operations, CoverCrypt authority growth and `version`. Both positional commands and named `--setup` / `--encrypt` forms are supported.

## CoverCrypt configuration

Create an attribute definition:

~~~json
{
  "dimensions": [
    {"name": "department", "attributes": ["finance", "it"]},
    {"name": "level", "attributes": ["user", "admin"]}
  ]
}
~~~

Save as `dimensions.json`. With the Python CLI you can pass `--config dimensions.json` on setup. You may also set `HCPABE_COVERCRYPT_CONFIG` and `HCPABE_COVERCRYPT_MODE` yourself. The CLI has `--mode hybridized|post_quantum|classic` (default hybridized).

## Unsigned file workflow

Create a directory `keys` first and a plaintext file `message.txt`. The following uses the **Python CLI** and named options:

~~~sh
python -m pq_cp_abe --setup --scheme covercrypt --config dimensions.json --file keys
python -m pq_cp_abe --genkey --scheme covercrypt --master-key keys/cpabe_msk.key --attributes "department::finance" --user-key finance.key
python -m pq_cp_abe --encrypt --scheme covercrypt --public-key keys/cpabe_pk.key --file message.txt --policy "department::finance" --ciphertext message.enc
python -m pq_cp_abe --decrypt --user-key finance.key --ciphertext message.enc --output recovered.txt
~~~

The setup path can be an existing directory, or a prefix when using the underlying native naming convention. See `python -m pq_cp_abe setup --help` for command syntax.

## Signing workflow

~~~sh
python -m pq_cp_abe --setup --scheme covercrypt --config dimensions.json --file signed --with-signing-keys --ml-dsa 65
python -m pq_cp_abe --genkey --scheme covercrypt --master-key signed_msk.key --attributes "department::finance" --user-key signed-user.key
python -m pq_cp_abe --encrypt --scheme covercrypt --sign --public-key signed_pk.key --signing-key signed_ml-dsa_sk.key --file message.txt --policy "department::finance" --ciphertext signed.enc --aes-bits 192 --ml-dsa 65
python -m pq_cp_abe --decrypt --verify --user-key signed-user.key --verification-key signed_ml-dsa_pk.key --ciphertext signed.enc --output verified.txt
~~~

- `--with-signing-keys`: add an ML-DSA keypair during setup; **does not sign the ABE keys**.
- `--sign`: sign data in the encryption flow.
- `--verify`: decrypt and require valid signature verification.
- `--ml-dsa {44,65,87}`: choose set when generating signing keys or signing (default 87).
- `--aes-bits {128,192,256}`: choose AES size for encryption (default 256).
- The older `--pqc`/`setup-pqc` aliases are supported for compatibility but are less descriptive.

When setup uses `--with-signing-keys`, the new signature files use the `ml-dsa` label; legacy naming may use `pqc`. Keys are not interchangeable across ML-DSA parameter sets.

## Python API file functions

If you do not want to invoke the CLI, the [functional API](api.md#functional-operations) exposes `setup_files`, `setup_files_with_signing`, `generate_secret_key_file`, `encrypt_file` and `decrypt_file`. These operate on **native host paths** and raise typed Python errors.

CoverCrypt's file-based key issuing persists authority/tracing metadata; coordinate concurrent writes to the same master key. For raw C ABI commands and installation of the standalone native executable, see the [repository CLI guide](../../native/cli.md).

## Platform notes

On Windows CMD, use `set HCPABE_COVERCRYPT_CONFIG=...`; in PowerShell use `$env:HCPABE_COVERCRYPT_CONFIG = "..."`; in Bash use `export HCPABE_COVERCRYPT_CONFIG=...`. Passing `--config` avoids depending on shell syntax.
