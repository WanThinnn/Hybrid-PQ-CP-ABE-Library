# Upstream attribution

This directory vendors CoverCrypt from Cosmian for integration work in Hybrid-CP-ABE-Library.

- Upstream project: Cosmian CoverCrypt
- Repository: https://github.com/Cosmian/cover_crypt
- Vendored version: v16.0.1
- Vendored commit: 492de850b51c73123e5fc3e96ecc64b360fbf39b
- License: BUSL-1.1 (see `LICENSE.md` in this directory)

Upstream authors listed in `Cargo.toml`:

- Théophile Brezot <theophile.brezot@cosmian.com>
- Bruno Grieder <bruno.grieder@cosmian.com>
- Hugo Rosenkranz-Costa <hugo.rosenkranz@cosmian.com>
- Emmanuel COSTE <emmanuel.coste@cosmian.com>

The original README, changelog, license, Cargo metadata, and CoverCrypt paper are retained alongside the vendored source. Local integration changes should remain clearly distinguishable from upstream code.

Local integration patch: the manifest omits example/benchmark targets whose
source directories are not included in this snapshot. Library source and its
cryptographic primitives are unchanged. `combine` in
`src/abe/policy/access_structure.rs` appends combinations without cloning
the complete intermediate vector; a differential test checks that the points,
security modes, activation statuses, and ordering match the original algorithm.
Use `cargo test --lib` for the
vendored upstream unit tests.

Local integration API: `generate_user_secret_key_restricted` generates signed
user keys only for the projections and hierarchy inheritance of explicitly
granted dimensions. The C bridge uses this API so a missing user attribute does
not become a wildcard. The original upstream key-policy API, primitives and
serialization formats are retained unchanged.
