# Upstream

- Project: librabe-ffi
- Repository: https://github.com/WanThinnn/librabe-ffi
- Vendored commit: `ff828d13a635042c9569cfb29117f299b553f946`
- Maintainer/vendor source: WanThinnn

This source is vendored so Hybrid-CP-ABE-Library can build its AC17 bridge without requiring a separate clone.

Local integration note: `build = false` is set in `Cargo.toml` because upstream `build.rs` only regenerates the already-vendored `rabe.h` via cbindgen/cargo-expand. The vendored `rabe.h` also adds a standard include guard plus `extern "C"` guards so C++ consumers use the Rust FFI's C ABI without symbol mangling. The cryptographic Rust source is otherwise unchanged.
