---
icon: lucide/network
---

# Architecture and schemes

!!! note
    This library provides two distinct PQC capabilities: optional **ML-DSA-87**
    signatures in the Sign-then-Encrypt flow through `liboqs`, and native
    **CoverCrypt** key encapsulation with **ML-KEM-768** in `hybridized` or
    `post_quantum` mode. ML-DSA-87 signatures alone do not make AC17 or TKN20
    quantum-resistant.

!!! important
    AC17 and TKN20 remain classical pairing-based ABE. CoverCrypt uses
    Curve25519 + ML-KEM-768 by default (`hybridized` mode), or can be configured
    for `post_quantum` or `classic` mode. ML-DSA-87 signing is optional and
    independent of the CoverCrypt mode. Historical v5.2 benchmark results below
    describe AC17/TKN20 only.

## Native interface and source layout

For a complete WebAssembly build on Linux (AC17, TKN20, CoverCrypt, AES-GCM and
ML-DSA-87), run `make wasm -j8` and `make wasm-test -j8` after installing the
toolchains in [bindings/wasm/README.md](../../bindings/wasm/README.md). The standalone
`Makefile.wasm` builds the static archive and browser/Node.js package separately
from native DLL/SO outputs.

The v5.2 public function names and parameters remain unchanged. Select
`CPABE_SCHEME_AC17`, `CPABE_SCHEME_TKN20` or `CPABE_SCHEME_COVERCRYPT` in the existing
`*_with_scheme` functions. Decryption reads the scheme from the ciphertext.
Existing default functions continue to select AC17. Keys are specific to a scheme;
changing the selection does not convert existing keys or ciphertexts.

Windows core builds publish `libcpabe_tkn20.dll` beside the public library in
`lib/` and beside the CLI in `build/artifacts/windows/`. Python bindings load
the public library and its runtime dependencies from `lib/`.

```text
src/hybrid-pq-cp-abe.cpp       Public interface and forwarding
src/core/abe-setup.cpp         Setup and optional signing-key generation
src/core/abe-genkey.cpp        User-key generation
src/core/abe-encrypt.cpp       Encryption and optional signing
src/core/abe-decrypt.cpp       Decryption and optional verification
src/schemes/                  ac17.cpp, tkn20.cpp, covercrypt.cpp
src/crypto/                   aes-gcm.cpp, ml-dsa.cpp
```

All three scheme adapters provide the same eight operations in
`include/hybrid_pq_cp_abe/cpabe-scheme.h`: `setup`, `setupBuffer`, `genkey`,
`genkeyBuffer`, `encapsulate_key`, `decapsulate_key`, `load_pk` and `load_sk`,
each prefixed with its scheme name. The public library interface remains in
`include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h`.

For CoverCrypt setup, set `HCPABE_COVERCRYPT_CONFIG` to the path of a JSON
configuration. Set `HCPABE_COVERCRYPT_MODE` to `hybridized` (default),
`post_quantum` or `classic`. `hybridized` combines Curve25519 with ML-KEM-768;
`post_quantum` uses the post-quantum mode, while `classic` selects the
classical mode. This setting controls CoverCrypt's key-encapsulation
confidentiality; it is separate from the optional ML-DSA-87 signing flag.
Applications load their own `.env` files and map their scheme setting to the
enum; the library reads the process environment.

```json
{"dimensions":[{"name":"admin","attributes":["present","absent"]},{"name":"it","attributes":["present","absent"]}]}
```

This configuration accepts the existing attribute list `admin it` and positive
policies such as `admin AND it` or `admin OR it`. Bare names are mapped to the
corresponding `<name>::present` attribute. For native dimensions/hierarchies,
use qualified policies such as `Department::FIN && Security::TOP`. CoverCrypt
does not translate the TKN20 `NOT` syntax; unsupported policies fail explicitly.

For a quick CLI smoke test, use the checked-in [scripts/covercrypt-demo.json](../../scripts/covercrypt-demo.json)
with `Department::{IT,HR}` and `Level::{USER,ADMIN}`. Run `pq-cp-abe --help` for CMD,
PowerShell and Linux/macOS environment commands and a setup/keygen/encrypt/decrypt
example. The demo contains only attribute definitions, not keys. Setup requires
`HCPABE_COVERCRYPT_CONFIG`; the CLI does not automatically read `.env` files.

### Native PQC with CoverCrypt

CoverCrypt's native PQC mode protects the ABE key-encapsulation path with
ML-KEM-768. This depends on the selected CoverCrypt mode. On Linux/macOS:

```sh
export HCPABE_COVERCRYPT_CONFIG=scripts/covercrypt-demo.json
export HCPABE_COVERCRYPT_MODE=hybridized
mkdir -p keys
build/artifacts/linux/pq-cp-abe setup --scheme covercrypt ./keys/demo
build/artifacts/linux/pq-cp-abe genkey --scheme covercrypt ./keys/demo_msk.key "Department::IT Level::ADMIN" ./keys/user.key
```

Use `post_quantum` to select CoverCrypt's post-quantum mode or `classic` for
its classical mode. The default is `hybridized`. For optional ML-DSA signatures
on any scheme, use `setup --with-signing-keys`, `encrypt --sign`, and
`decrypt --verify`. The default signature parameter set is ML-DSA-87.

User keys grant only the named dimensions and their hierarchy inheritance. A
`Department::IT` key can decrypt that department's policy, but cannot decrypt
`Department::IT && Level::ADMIN`. The bridge uses restricted user-key generation
instead of upstream's native wildcard behavior for omitted dimensions.
Keys issued by an older bridge retain their existing rights: revoking those
rights requires a new authority, new user keys and re-encryption under the new
public key. Rebuilding the program alone does not revoke old key material.

The file-based CoverCrypt key-generation function persists the updated MSK.
The v5.2 buffer function remains stateless and does not retain the user registry
used by CoverCrypt tracing; this library does not expose tracing operations.
Serialize access to authority files when issuing keys from multiple processes.
See `bindings/covercrypt/README.md` for the native bridge and its upstream license.

### Extend a CoverCrypt authority

`add_dimension` and `add_attribute` use the existing MSK and upstream
`AccessStructure` operations followed by `Covercrypt::update_msk`. They retain
existing secrets rather than running `setup` again. The commands return a new
MSK/PK pair under an unused output prefix; the input keys are left unchanged.

Add a new E dimension to the demo authority:

```sh
build/artifacts/windows/pq-cp-abe.exe add_dimension --scheme covercrypt ./keys/demo_msk.key scripts/covercrypt-add-new-attrbutes.json ./keys/demo-v2
```

On Linux/macOS, use `build/artifacts/linux/pq-cp-abe` or
`build/artifacts/macos/pq-cp-abe` respectively. `scripts/covercrypt-add-new-attrbutes.json` is one
dimension object, whereas the setup JSON contains a `dimensions` array.

For a new value in an existing dimension:

```sh
build/artifacts/windows/pq-cp-abe.exe add_attribute --scheme covercrypt ./keys/demo-v2_msk.key Department SALES ./keys/demo-v3
```

For hierarchical dimensions, the optional final argument is the existing
attribute after which the new value is inserted; without it, upstream assigns
the lowest rank. `HCPABE_COVERCRYPT_MODE` controls only the new attributes.

Retain **both** updated master keys and use the updated MSK for subsequent
`genkey` operations. Old user keys retain their previous rights on old and new
ciphertexts using those rights. They do not automatically gain E. Grant E by
issuing a new authorized key from the updated MSK, for example:

```sh
build/artifacts/windows/pq-cp-abe.exe genkey --scheme covercrypt ./keys/demo-v2_msk.key "Department::IT && Level::ADMIN && E::present" ./keys/user-e.key
```

Signing keys can be reused after growing an authority.
Serialize authority-management operations and review the new pair before
switching applications to it. Output files must not already exist.

This follows upstream's [update_msk](https://docs.rs/cosmian_cover_crypt/latest/cosmian_cover_crypt/struct.Covercrypt.html#method.update_msk)
and [AccessStructure](https://docs.rs/cosmian_cover_crypt/latest/cosmian_cover_crypt/struct.AccessStructure.html)
APIs. Adding rights differs from `rekey` (rotate secrets), `refresh_usk` (refresh
an existing key's revisions), or `prune_master_secret_key` (irreversibly remove
old revisions). Growth does not revoke previously issued keys.

The library uses a **hybrid KEM/DEM-style architecture**: ABE protects a
randomly generated secret under the access policy, SHA3-256 derives the
AES-256 key, and AES-GCM handles the bulk payload. CoverCrypt's `hybridized`
or `post_quantum` mode uses ML-KEM-768 in the ABE encapsulation path.
With `encrypt --sign`, the CLI applies **ML-DSA Sign-then-Encrypt**
before the payload enters the hybrid encryption pipeline.

For the current binary format, AES-GCM authenticates the header as AAD:

`[Version | Scheme | IV | Encapsulated-Key Length | Encapsulated CP-ABE Key]`

The ML-DSA-87 layer signs:

`[PolicyLen | Policy | Plaintext]`

before encryption.
