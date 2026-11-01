# Vault tests

From the repository root in your Linux environment (including a chosen WSL distro):

```sh
make test-vault -j8
```

Compilation happens directly on Linux. First, Go tests execute the production backend
through Vault SDK `HandleRequest` with in-memory storage and the real native
library. Then Docker runs only a Vault development service loading that build.
The HTTP test checks setup, key generation, binary encrypt/decrypt and rejected
users for AC17/TKN20/Covercrypt with and without ML-DSA. Backend tests also cover
Covercrypt AND/OR, signed ciphertext tampering, invalid inputs, stored-scheme
validation and obsolete signing-state removal. Native version is compared with
the repository VERSION file. JSON setup/growth tests cover all three encryption
modes, old/new key compatibility, signing-key continuity, persistence after
backend reload, independent mounts, malformed/duplicate dimensions and failed
storage commits. Crypto operations use real keys and ciphertexts.

Requirements beyond the normal core/Go toolchain: Python 3 and an accessible
Linux Docker daemon. The Dockerfile is runtime-only; its Vault version can be
selected using the HTTP runner's `--vault-version` argument. No plugin source
or archive is copied into the image.
Set `VAULT_RUNTIME_BASE` (or the runner's `--runtime-base`) to a Debian/Ubuntu
runtime base compatible with your build host's glibc when needed.

The Docker test uses a unique temporary container, random localhost port and
JSON configuration sent through the API. It mounts no Covercrypt JSON file and
sets no Covercrypt environment variables. It cleans up its own container and leaves existing
containers untouched. The service is for development only, with token `root`.

To test a separate dedicated development mount instead:

```sh
export VAULT_ADDR=http://127.0.0.1:8201
export VAULT_TOKEN=root
export VAULT_ABE_MOUNT=abe
python3 plugins/vault/tests/test_vault.py
```

This manual mode calls setup repeatedly and replaces that mount's authority.
Do not point it at real data. The script sends its Covercrypt JSON through
setup requests. No Python packages beyond the standard
library are needed.

`tests/test_plugin.sh` and `tests/test_plugin.ps1` are compatibility wrappers
around `make test-vault`; neither copies code nor compiles inside Docker.
