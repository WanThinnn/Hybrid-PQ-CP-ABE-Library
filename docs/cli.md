# Command-line usage

## Command reference

Use `./bin/main` from an extracted Unix release or `bin\main.exe` on
Windows. The examples use `main` as shorthand for that executable.

```sh
Usage: main [command] [--scheme <name>] [--pqc] [options]
Usage: main setup [--scheme <name>] <path_to_save_file>
Usage: main genkey [--scheme <name>] <master_key_file> <attributes> <private_key_file>
Usage: main encrypt [--scheme <name>] <public_key_file> [pqc_private_key] <plaintext_file> <policy> <ciphertext_file>
Usage: main decrypt <private_key_file> [pqc_public_key] <ciphertext_file> <recovertext_file>
```

Example commands (Standard Mode):
```sh
mkdir -p test_case
printf '%s\n' 'Example plaintext' > test_case/plaintext.txt
main setup --scheme tkn20 test_case
main genkey --scheme tkn20 "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
main encrypt --scheme tkn20 "test_case/cpabe_pk.key" "test_case/plaintext.txt" "((A and C) or E)" "test_case/ciphertext.txt"
main decrypt "test_case/cpabe_sk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```

Example commands (Optional ML-DSA-87 Signatures):

The `--pqc` option enables ML-DSA-87 Sign-then-Encrypt signatures; it does not
change the ABE scheme's confidentiality properties. AC17 and TKN20 remain
classical. To use native post-quantum key encapsulation, select CoverCrypt and
set `HCPABE_COVERCRYPT_MODE` to `hybridized` (default) or `post_quantum` as
described in the [architecture and scheme guide](architecture.md#native-pqc-with-covercrypt).

```sh
main setup --scheme tkn20 --pqc test_case
main genkey --scheme tkn20 "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
main encrypt --scheme tkn20 --pqc "test_case/cpabe_pk.key" "test_case/pqc_sk.key" "test_case/plaintext.txt" "\"A\"" "test_case/ciphertext.txt"
main decrypt --pqc "test_case/cpabe_sk.key" "test_case/pqc_pk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```
