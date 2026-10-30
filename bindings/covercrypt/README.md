# Native CoverCrypt bridge

This project-owned Rust crate exports a C ABI for the vendored CoverCrypt v16
KEM. It statically includes Curve25519 + ML-KEM-768 and supports Classic,
PostQuantum and Hybridized rights. The C++ adapter is under
`src/schemes/`; this is a native dependency, not a runtime plugin.

Setup takes JSON such as:
```json
{"dimensions":[{"name":"Department","attributes":["FIN","HR"]},{"name":"Security","attributes":["LOW","TOP"],"hierarchical":true}]}
```
Hierarchical attributes are listed from lowest to highest. All attributes use
the requested mode; Hybridized is the C++ default. Policy strings use upstream
syntax (`Department::FIN && Security::TOP`) and ASCII identifiers.

The low-level `cc_genkey` bridge returns an updated MSK for callers that retain
CoverCrypt's user registry. The v5.2 library file interface persists that state;
its stateless buffer interface generates usable keys without retaining tracing
registration. The `cc_genkey_ephemeral` entry point implements this existing
Buffer behavior without serializing an updated MSK that would be discarded.
File/authority callers must use `cc_genkey` and persist the returned MSK.
No tracing interface is exported by this library.

Both `cc_genkey` and `cc_genkey_ephemeral` use restricted user-key generation:
dimensions omitted from a user policy grant no attributes. For example, a user
key for `Department::IT` cannot decrypt `Department::IT && Level::ADMIN`, but can
decrypt `Department::IT`. Hierarchy inheritance is retained. This differs from
upstream's native key-policy API, where omitted dimensions are unconstrained;
that native Rust API is left unchanged. Conflicting values of one dimension in
the same AND clause are rejected; use OR for alternatives.

Keys already issued using the previous unrestricted bridge retain their old
rights. To revoke those rights, replace the affected authority and user keys
and re-encrypt affected data under the new public key. Rebuilding the library
alone cannot revoke cryptographic key material already issued.

Keys and KEM encapsulations are opaque upstream serializations. The C++ adapter
exposes the same integer status/buffer operations as AC17/TKN20. It uses the KEM
secret with AES-GCM to protect the supplied key buffer, then the shared core
handles the payload and optional ML-DSA-87 signing. No cryptographic primitives
are reimplemented. Rust panics are caught at the C bridge; Rust-owned buffers
are zeroized and freed with `cc_buffer_free`.

`make deps -j8` builds/checks all five native dependencies and stages both static
and shared CoverCrypt libraries and the C header:

| Platform | Shared library under `build/deps/<platform>/lib/covercrypt/` |
| --- | --- |
| Windows (MSVC x64) | `covercrypt_ffi.dll` and import library `covercrypt_ffi.dll.lib` |
| Linux | `libcovercrypt_ffi.so` |
| macOS | `libcovercrypt_ffi.dylib` |

The existing static linkage of the main hybrid library is retained. Applications
that load the standalone shared library must use its `cc_*` API and release
its allocations through that same library's `cc_buffer_free`.

`make test -j8` (or its alias `make tests -j8`) runs the native C++ integration
tests together with the project tests. Vendored Rust unit tests can also be run
with `cargo test --locked --release --manifest-path vendor/cover_crypt/Cargo.toml --lib`.
After `make deps -j8`, run
`python -m unittest discover -s tests -p test_covercrypt_shared.py -v` from the
repository root to check the standalone library through its dynamic C ABI.
CoverCrypt is selected with `CPABE_SCHEME_COVERCRYPT` through the existing
library functions. Setup reads `HCPABE_COVERCRYPT_CONFIG` (JSON file path) and
`HCPABE_COVERCRYPT_MODE` (`hybridized`, `post_quantum`, or `classic`). The CLI's
scheme option must map to that enum; applications keep the existing function
signatures. See the root README for legacy attribute syntax and configuration.

The bridge's original code is Apache-2.0. CoverCrypt and its dependencies retain
their respective licenses; upstream CoverCrypt is BUSL-1.1.
