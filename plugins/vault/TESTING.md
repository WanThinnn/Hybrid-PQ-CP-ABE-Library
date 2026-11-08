# Vault tests

From the repository root in your Linux environment (including a chosen WSL distro):

```sh
make test-vault -j8
```

To exercise the same HTTP suite on **real single-node Raft storage** with
Vault's default entry/request size limits, after building the Linux plugin:

```sh
python3 plugins/vault/tests/test_vault.py --docker --raft
# Check the 1.15.6 deployment line explicitly when needed:
python3 plugins/vault/tests/test_vault.py --docker --raft --vault-version 1.15.6
```

Only the uniquely named disposable fixture is initialized/unsealed. Its token
and single test share stay in memory; no deployment keys or volumes are used.
The fixture is removed in `finally`, including after test failures.

Compilation happens directly on Linux. First, Go tests execute the production backend
through Vault SDK `HandleRequest` with in-memory storage and the real native
library. Then Docker runs only an isolated single-node Raft service loading that build.
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
containers untouched. The service is for development only. Raft tests initialize
one temporary node and retain its share/token only in memory; `--docker`
without `--raft` uses Vault dev mode with the known fixture token `root`.

Additional backend tests cover bounded writes, chunk/manifest commit failures
(including commit-then-timeout), retained snapshots, corrupt/missing chunks,
retired format-2 reads with real cryptography, read-only recovery, concurrent
create-only setup, stale/wrong references and explicit signature selection.
HTTP tests include the 4/3/6/4/5/6 dimension cardinalities that previously created
a roughly 47.9-MB Base64 public key, signed/unsigned allow/deny, tamper rejection
and plugin-process reload. `make test-vault` and extracted Vault package
verification both select the Raft fixture.

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

## Verified local integration, 2026-11-08

- Linux plugin built through `go run scripts/build-vault.go -test` in Ubuntu
  WSL against the existing v6.0.0 shared native library: all 16 backend test
  groups passed. `go test -race ./... -count=1` also passed.
- All four HTTP test methods (including their per-scheme/signature subcases
  and the large six-dimension case) passed on disposable real Raft fixtures
  for Vault **1.15.6** and **2.0.4**, without increasing entry/request limits.
- Eight release-package regression tests passed, including shipping
  `AUTHORITY.md` with the matched plugin/shared runtime.
- On this Windows-mounted checkout, `GOFLAGS=-buildvcs=false` was supplied to
  the local Go build/test invocation because Go's automatic VCS status scan
  stalled. This is a local build option, not a committed dependency or a
  replacement for recording the source commit when preparing a release.

These checks did not upgrade an existing deployment or use its keys, database,
cloud storage or ciphertext. Multi-node HA, Consul storage and Enterprise seal
wrapping were not exercised. There is no claim of a completed application-level
CPQA upload/download rollout or a published library release.
