---
icon: lucide/terminal
---

# Command-line usage

## Command reference

Use `./bin/pq-cp-abe` from an extracted Unix release or `.\bin\pq-cp-abe.exe`
on Windows. Add the release's `bin` directory to `PATH` to run `pq-cp-abe`
from any directory. Run `pq-cp-abe --help` for an overview or
`pq-cp-abe encrypt --help` for one command's arguments.

To install from source, run `make install` in the repository using the native
build toolchain.

- Linux and macOS install to `/usr/local/bin` by default. For a user-local install,
  run `make install PREFIX="$HOME/.local"` and add `$HOME/.local/bin` to `PATH`.
  Use `DESTDIR` to stage a package without installing into the live system.
- Windows installs to `%LOCALAPPDATA%\Programs\pq-cp-abe\bin` by default and
  adds the directory to User PATH. Run `make install PREFIX="C:/path/to/prefix"`
  to choose another prefix, or `make install UPDATE_PATH=0` to stage files without
  changing User PATH. Open a new terminal after updating User PATH.

```sh
Usage: pq-cp-abe <command> [options] [arguments]
Usage: pq-cp-abe setup [--scheme <name>] <path_to_save_file>
Usage: pq-cp-abe genkey [--scheme <name>] <master_key_file> <attributes> <private_key_file>
Usage: pq-cp-abe encrypt [--scheme <name>] <public_key_file> [pqc_private_key] <plaintext_file> <policy> <ciphertext_file>
Usage: pq-cp-abe decrypt <private_key_file> [pqc_public_key] <ciphertext_file> <recovertext_file>
```

Example commands (Standard Mode):
```sh
mkdir -p test_case
printf '%s\n' 'Example plaintext' > test_case/plaintext.txt
pq-cp-abe setup --scheme tkn20 test_case
pq-cp-abe genkey --scheme tkn20 "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
pq-cp-abe encrypt --scheme tkn20 "test_case/cpabe_pk.key" "test_case/plaintext.txt" "((A and C) or E)" "test_case/ciphertext.txt"
pq-cp-abe decrypt "test_case/cpabe_sk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```

## CoverCrypt with ML-DSA signatures

CoverCrypt uses ML-KEM-768 for key encapsulation in its `hybridized` (default)
and `post_quantum` modes. The optional ML-DSA signature flow works with CoverCrypt,
AC17, and TKN20. [Architecture and scheme guide](../architecture/README.md#native-pqc-with-covercrypt)

- `setup --with-signing-keys` creates an ML-DSA key pair alongside the ABE keys.
  The signing and verification files are named `ml-dsa_sk.key` and `ml-dsa_pk.key`
  inside an output directory, or `demo_ml-dsa_sk.key` and `demo_ml-dsa_pk.key`
  with a prefix such as `demo`.
- `encrypt --sign` signs the data before encrypting it. Pass the secret signing key with `--signing-key`.
- `decrypt --verify` requires a valid signature before returning plaintext. Pass the public verification key with `--verification-key`.

ML-DSA-87 is the default. To use set 44 or 65, pass the same `--ml-dsa` value to
setup and encryption. Decryption detects the set from the ciphertext. Existing
scripts can continue to use `--pqc` as an alias for the signature action of each
command. Setup with only the legacy flag keeps the `pqc_sk.key` and `pqc_pk.key`
names.

```sh
export HCPABE_COVERCRYPT_CONFIG="$PWD/scripts/covercrypt-demo.json"
printf '%s\n' 'Example plaintext' > data.txt
pq-cp-abe --setup --scheme covercrypt --with-signing-keys --ml-dsa 87 --file demo
pq-cp-abe --genkey --scheme covercrypt --master-key demo_msk.key \
  --attributes "Department::IT && Level::ADMIN" --user-key user.key
pq-cp-abe --encrypt --scheme covercrypt --sign --public-key demo_pk.key \
  --signing-key demo_ml-dsa_sk.key --file data.txt \
  --policy "Department::IT && Level::ADMIN" --ciphertext data.enc
pq-cp-abe --decrypt --verify --user-key user.key \
  --verification-key demo_ml-dsa_pk.key --ciphertext data.enc --output recovered.txt
```
