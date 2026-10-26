# Native dependency build

The primary dependency sources are vendored in this repository. A fresh clone does not need separate clones of Crypto++, liboqs, librabe-ffi, or CIRCL.

Source of truth:

- `vendor/cryptopp/` — Crypto++ 8.9 source
- `vendor/liboqs/` — Open Quantum Safe source
- `vendor/librabe-ffi/` — AC17 Rust FFI source
- `vendor/circl/` — Cloudflare CIRCL v1.6.4 source
- `bindings/tkn20/` — project-owned C bridge over vendored CIRCL
- `vendor/cover_crypt/` — optional CoverCrypt source

Pinned revisions and upstream attribution are documented in `vendor/README.md` and each dependency's `UPSTREAM.md`.

## Build

From the repository root:

```sh
make deps
```

`make all`, `make static`, and `make test` automatically ensure dependencies are built first.

Dependency build cache:

```text
build/deps/windows/
build/deps/linux/
build/deps/macos/
```

Generated native libraries are copied into:

```text
lib/static/
lib/dynamic/
```

To force a clean dependency rebuild:

```sh
make deps-clean
make deps
```

## Toolchain requirements

Windows requires Visual Studio 2022/MSVC, CMake, Rust/Cargo, Go 1.24+, GNU Make, and a MinGW-w64 `gcc` for Go CGO/TKN20. Run from an x64 Native Tools prompt so `msbuild` and `lib.exe` are available.

Linux/macOS require a C/C++ toolchain, CMake, Make, Rust/Cargo, and Go 1.24+.

The major native dependency source trees are included in the repository. Cargo and Go may still fetch their own transitive registry/module dependencies on the first build if they are not already cached.
