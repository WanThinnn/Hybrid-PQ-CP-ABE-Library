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
registration. No tracing interface is exported by this library.

Keys and KEM encapsulations are opaque upstream serializations. The C++ adapter
exposes the same integer status/buffer operations as AC17/TKN20. It uses the KEM
secret with AES-GCM to protect the supplied key buffer, then the shared core
handles the payload and optional ML-DSA-87 signing. No cryptographic primitives
are reimplemented. Rust panics are caught at the C bridge; Rust-owned buffers
are zeroized and freed with `cc_buffer_free`.

`make deps` stages the static library and C header. `make test-covercrypt` runs
the native C++ integration tests; `make test-covercrypt-rust` runs the vendored
upstream library tests. `make test` includes the native integration tests.
CoverCrypt is selected with `CPABE_SCHEME_COVERCRYPT` through the existing
library functions. Setup reads `HCPABE_COVERCRYPT_CONFIG` (JSON file path) and
`HCPABE_COVERCRYPT_MODE` (`hybridized`, `post_quantum`, or `classic`). The CLI's
scheme option must map to that enum; applications keep the existing function
signatures. See the root README for legacy attribute syntax and configuration.

The bridge's original code is Apache-2.0. CoverCrypt and its dependencies retain
their respective licenses; upstream CoverCrypt is BUSL-1.1.
