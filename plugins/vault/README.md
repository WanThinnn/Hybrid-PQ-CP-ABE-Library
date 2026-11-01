# Vault ABE plugin on Linux

The plugin calls the public C API in the root `include/hybrid_pq_cp_abe/`
directory and links the current `lib/libhybrid-pq-cp-abe.so`. All AC17, TKN20,
Covercrypt, AES-GCM and ML-DSA implementations come from the main native library.
There are no copied crypto sources, private static archives or sync scripts.

## Build on Linux

From the repository root on Linux (Ubuntu, Kali, Mint, etc.), using the normal native build toolchain:

```sh
make deps -j8
make vault -j8
make test-vault -j8
make clean-vault
```

`make vault` incrementally builds the shared core and then the Go plugin on
Linux itself. Go must satisfy `vault-plugin-abe/go.mod` (Go's automatic
toolchain download can provide it). The plugin uses CGO and the same public
header/library output as other consumers. Docker is not part of compilation.
`make deps` is needed after modifying dependency sources; a missing ready marker
also triggers it automatically, following the main project's existing rules.
`make clean-vault` removes only `build/artifacts/linux/vault/`; native core,
dependency output and Go caches are retained. `make clean-deps` removes the
native dependency output for the current platform.

On Windows, enter your chosen Linux/WSL distribution first, then run the same
commands from its shell. The Makefile does not select or launch a distribution:

```sh
make vault
make test-vault
```

Only Linux artifacts are produced. Native Windows/macOS invocations print an
explanation and exit without compiling a plugin for the wrong platform.

Output is collected under `build/artifacts/linux/vault/`:

- `vault-plugin-abe`
- `libhybrid-pq-cp-abe.so`

Release CI also builds/tests this plugin on its Linux runner and publishes a
separate `vault-plugin-abe_linux_x86_64_v<VERSION>.zip` alongside the native SDK
packages. The archive includes both runtime files, a Covercrypt configuration
example, documentation and third-party notices. Its extracted contents are
tested against a Vault service before upload. Register `vault-plugin-abe`
inside the archive; the executable keeps its standard name.

Deploy both files together. The loader uses the plugin's own directory as a
runtime library search path. The build helper fingerprints the public headers
and native library to invalidate CGO's cache after native changes; no source
sync or global Go cache reset is needed. Native buffers are released through
the same library's `freeBuffer` function.

## Test with Vault running in Docker

`make test-vault` first runs backend tests with real native cryptography, then
starts an isolated Vault development service in Docker, registers the already
built Linux plugin and tests its HTTP endpoints. The runtime image contains
Vault and runtime dependencies only: it has no compiler and never builds the
plugin. The test mounts the Linux artifacts read-only, uses a random localhost
port and a unique container name, and removes only its own container afterward.
It does not touch existing Vault services or mounts.

See [TESTING.md](TESTING.md) for test coverage and manual HTTP testing.

## Covercrypt configuration and API

Send JSON text directly with `config_json`. With Vault CLI, `@file` reads a
file on the **client**, not on the Vault server. No Covercrypt file, environment
variable or JSON volume mount is required on the server. Each mount stores its
own JSON and mode alongside its keys. Modes are `classic`, `post_quantum`, and
`hybridized` (default); `pqc=true` independently enables ML-DSA.

```sh
vault write abe/setup scheme=covercrypt config_json=@scripts/covercrypt-demo.json mode=hybridized pqc=true
vault write abe/genkey scheme=covercrypt attributes="Department::IT Level::ADMIN"
vault write abe/encrypt scheme=covercrypt public_key="<BASE64_PK>" plaintext="aGVsbG8=" policy="Department::IT && Level::ADMIN"
vault write abe/decrypt secret_key="<BASE64_SK>" ciphertext="<BASE64_CT>" pqc_public_key="<BASE64_PQC_PK>"
```

The same endpoints accept `ac17` and `tkn20`. Genkey must use the stored
authority's scheme; decrypt reads the scheme from the ciphertext. Setup returns
`public_key`, `scheme`, `pqc`, `native_version`, `revision`, and optional `pqc_public_key`.
Covercrypt also returns `config_json` and `mode`.
Master secrets stay in Vault storage. Encrypt uses the stored signing key or
an explicit `pqc_private_key`; decrypt verifies when `pqc_public_key` is supplied.
Treat returned user keys as secrets.

### Add a dimension without replacing the authority

```sh
vault write abe/add_dimension dimension_json='{"name":"E","attributes":["present","absent"],"hierarchical":false}'
# Or: vault write abe/add_dimension dimension_json=@client-side-dimension.json
```

`dimension_json` is a single dimension object, whereas setup takes a
`{"dimensions":[...]}` configuration. Growth uses the stored authority's mode.
The endpoint returns the updated `public_key`, complete `config_json`, mode
and revision. Use this new public key for future encryption. User keys already
issued retain their old rights and can decrypt old data and new data requiring
those rights. They gain no E rights automatically. Issue a new authorized key
to grant E:

```sh
vault write abe/genkey scheme=covercrypt attributes="Department::IT Level::ADMIN E::present"
```

The MSK, PK, JSON and mode are committed in one seal-wrapped Vault record;
signing keys are retained. Malformed JSON, duplicate dimensions or failed
storage writes leave the existing authority unchanged. Backend reloads read
the saved state without any configuration file.

Each mount stores one authority. Calling setup again replaces it; use
`add_dimension` to grow it. Secrets from the previous plugin's storage layout
remain readable for existing genkey/signing operations. That layout did not
save JSON/mode, so growth on a legacy authority returns an explicit error;
it never guesses settings or recreates its master keys. Existing authorities
are not automatically migrated or replaced by upgrading the plugin.

## Deploy an existing build

Set `plugin_directory` in Vault's server configuration to the absolute artifact
directory. Calculate the plugin executable's SHA-256 and register it:

```sh
vault plugin register -sha256=<SHA256> -command=vault-plugin-abe secret vault-plugin-abe
vault secrets enable -path=abe vault-plugin-abe
```

After rebuilding a deployed plugin, update its catalog checksum and reload it
through your Vault deployment procedure. Build and deploy for compatible CPU
architecture and glibc versions; the development service uses Ubuntu 24.04.
For a build using a newer glibc, choose a compatible Debian/Ubuntu runtime
base, for example `VAULT_RUNTIME_BASE=debian:trixie make test-vault`.
This selects only the service image; compilation still uses your Linux host.
