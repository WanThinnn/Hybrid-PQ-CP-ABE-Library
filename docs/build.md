# Build from source

## Building (Multi-OS)
> [!IMPORTANT]
> This library integrates the following cryptographic primitives and dependencies:
- [CryptoPP Library](https://github.com/weidai11/cryptopp)
- [CP-ABE AC17 Scheme](https://eprint.iacr.org/2017/807) (via [Rabe-ffi](https://github.com/WanThinnn/librabe-ffi.git))
- [CP-ABE TKN20 Scheme](https://eprint.iacr.org/2019/966) (via [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/abe))
- [Open Quantum Safe Library](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe - used for optional ML-DSA-87 signatures)
- [HashiCorp Vault Secrets Engine](../plugins/vault/README.md) (optional Go plugin for Enterprise Cryptography-as-a-Service)
- [Cosmian CoverCrypt](https://eprint.iacr.org/2025/544) via [Cosmian CoverCrypt](https://github.com/Cosmian/cover_crypt) (native ABE integration with Classic, PostQuantum and Hybridized modes; see `vendor/cover_crypt/`)

> [!NOTE]
>
> **Dependency source of truth:** third-party source is vendored under `vendor/`. Built dependency headers and libraries are normalized under `build/deps/<platform>/`; the top level of that directory contains only `include/` and `lib/` after a successful dependency build.

For maintainer-only upstream Git histories and update commands, see
[vendor/README.md](../vendor/README.md). Source stays vendored; ordinary clones do
not require submodule initialization.

1. Clone the repository:
    ```sh
    git clone https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library.git
    cd Hybrid-PQ-CP-ABE-Library
    ```

Required toolchains include CMake, Rust/Cargo, GNU Make, and a native C/C++
compiler. Use the Go version declared in [the TKN20 module](../bindings/tkn20/go.mod)
and check [the Vault module](../plugins/vault/vault-plugin-abe/go.mod) when
building the plugin. Windows also requires Visual Studio 2022/MSVC and
MinGW-w64 `gcc` for Go CGO/TKN20.

The root `VERSION` file is the version source of truth. Make generates the public
`include/hybrid_pq_cp_abe/version.h` header and embeds that value in the library
and CLI. Changing `VERSION` triggers an incremental rebuild; deployed binaries
do not need to find a `VERSION` file at runtime.

### Configure a new machine

The single `configure` file checks the host toolchain without installing or
downloading anything. Missing tools produce a nonzero exit status. Use
`--install` explicitly to install missing tools; OS installers may request
administrator access or interactive completion.

Linux/macOS (no Make or Python needed to start the check):

```sh
chmod +x configure
./configure
./configure --install
. ./build/tools/activate.sh
```

On Linux, WSL, macOS, or Windows MSYS2, use `sh ./configure --wasm` after
activating Emscripten to check the WebAssembly toolchain. Combine it with
`--install` to install the standard host tools. See the
[WebAssembly guide](../bindings/wasm/README.md) for platform setup.

For a custom Linux/macOS toolchain with an explicitly controlled `PATH`, use
`HCPABE_CONFIGURE_DISCOVER_PATHS=0 ./configure`. This disables automatic search
paths for bundled Go, Cargo and Homebrew; ordinary checks retain discovery by
default. Configure tests use this mode so runner-installed tools cannot hide
the missing/old tool versions being tested.

Linux installation supports apt, dnf, pacman and zypper. Go is downloaded from
the official Go release metadata with SHA256 verification when needed. macOS
uses Apple Command Line Tools and Homebrew; finish any Apple installer dialog
and rerun `configure --install` if prompted. Rust uses the official rustup
installer. Activation adds local tools to this shell's PATH.

On a fresh Windows machine, PowerShell is already available; Bash is not
required. Run from the repository root to execute the Windows section embedded
in the same file:

```powershell
$text = Get-Content .\configure -Raw
$setup = [scriptblock]::Create(($text -split '(?m)^# WINDOWS CONFIGURE\r?$', 2)[1])
& $setup                 # Check only
& $setup -Install        # Install missing tools
& $setup -Wasm           # Check Windows WASM tools through MSYS2 when Emscripten is on PATH
cmd /k build\tools\activate.cmd
```

The Windows installer uses WinGet for Visual Studio C++ Build Tools, MSYS2, Go
and rustup, then MSYS2's package manager for Make/CMake/MinGW. If WinGet is
missing, install Microsoft's App Installer from <https://aka.ms/getwinget> first.
Use the activated x64 command prompt for subsequent `make` commands; it keeps
MSVC's linker ahead of the unrelated MSYS `link.exe`. No `make prepare` or
library-specific Make targets are needed.

Build order from a fresh clone:

1. **Build native dependencies**
   ```sh
   make deps -j8
   ```
   This builds Crypto++, liboqs, librabe-ffi, CIRCL/TKN20, and CoverCrypt. liboqs is configured as a minimal ML-KEM + ML-DSA build only: ML-KEM-512/768/1024 and ML-DSA-44/65/87. The `-jN` budget is distributed across the five dependency builds without oversubscribing the requested total.

2. **Dependency output**
   ```text
   build/deps/<platform>/
   ├── include/
   │   ├── cryptopp/
   │   ├── liboqs/
   │   ├── rabe/
   │   └── tkn20/
   └── lib/
       ├── cryptopp/
       ├── liboqs/
       ├── rabe/
       └── tkn20/
   ```
   Temporary CMake/Cargo/Go/Crypto++ build trees are removed after success. Fingerprint metadata is kept inside each `lib/<dep>/` directory so unchanged dependencies can be skipped on the next build.

3. **Build the Hybrid-CP-ABE native core**
   ```sh
   make -j8
   ```
   The core consumes headers and libraries directly from `build/deps/<platform>/`. After a successful dependency build, `build/deps/<platform>/lib/.ready` marks the dependency set as ready; normal `make -jN` builds do not run the dependency scripts again and go straight to the native core.

4. **Run tests**
   ```sh
   make test -j8
   ```

On Windows, run these commands from an **x64 Native Tools Command Prompt for VS 2022**. Windows uses the MSVC x64 ABI; `librabe-ffi` is forced to `x86_64-pc-windows-msvc`, while TKN20 uses Go/MinGW only behind a C ABI DLL plus an MSVC import `.lib`.

The native C++ library, Crypto++, and liboqs use the dynamic MSVC runtime (`/MD`). Crypto++ still links as a static `.lib`. The dependency builder removes byte-identical duplicate archive members from the Rust static library while preserving its symbols and COFF linker indexes.

After `make`, the build prints the exact include, dependency-library, native-library, shared-library, runtime-DLL, and CLI output paths. `include/` and `lib/` at the repository root are project-only: `include/hybrid_pq_cp_abe/` contains the public Hybrid-CP-ABE API, while `lib/` contains the project static and shared libraries side by side. All third-party headers/libraries stay exclusively under `build/deps/<platform>/`.

Normal core builds are incremental. Use `make clean` only to remove the project core/object output. Use `make clean-deps` to remove the complete dependency output for the current platform.

See [build/README.md](../build/README.md) for the output layout. Keep logs under
`build/logs/`, local reports under `build/reports/`, and temporary fixtures under
`build/tmp/`. Reusable diagnostic scripts live in `scripts/diagnostics/`.

**Available Make Commands:**
- `make deps -j8`: Build/check the five native dependencies and print their final include/library layout.
- `make -j8`: Build the native C++ core directly from the existing dependency output. It only auto-builds dependencies when the ready marker is missing (fresh clone or after `make clean-deps`).
- `make clean-deps`: Remove `build/deps/<platform>/`.
- `make static`: Build only the project static library.
- `make shared`: Build only the project shared library.
- `make executable`: Build only the CLI executable.
- `make test -j8`: Incrementally build and run the tests.
- `make tests -j8`: Alias for `make test -j8`.
- `make vault -j8`: Build the Vault plugin on Linux against the current shared core.
- `make test-vault -j8`: Build/test on Linux, then run HTTP tests with only the Vault service in Docker.
- `make clean-vault`: Remove only the Linux Vault plugin output under `build/artifacts/linux/vault/`.
- `make abi-info`: Show the platform ABI/toolchain policy.
- `make clean`: Remove only project core/object output.

If installed, `sccache` is used automatically where supported. liboqs prefers Ninja when available.

On Windows, `make deps` builds Crypto++ as both a static library and an ordinary,
non-FIPS DLL with the upstream DLL API. `build/deps/windows/lib/cryptopp/` contains
`libcryptopp.lib` (static), `cryptopp.dll`, and `cryptopp.lib` (DLL import library).
DLL consumers include `cryptopp/dll.h` first and link `cryptopp.lib`.

## Repository Layout

```text
src/                    C++ core implementation only
include/                Public C/C++ API
bindings/python/        Python binding
bindings/tkn20/         Project-owned Go/C bridge for CIRCL TKN20
plugins/vault/          Optional HashiCorp Vault plugin
bindings/covercrypt/    Native Rust/C bridge for CoverCrypt
vendor/cryptopp/        Vendored Crypto++ source
vendor/liboqs/          Vendored Open Quantum Safe source
vendor/librabe-ffi/     Vendored AC17 Rust FFI source
vendor/circl/           Vendored Cloudflare CIRCL v1.6.4 source
vendor/cover_crypt/     Vendored Cosmian CoverCrypt source
lib/                    Generated/prebuilt native libraries
tests/cpp/              Native test suite
build/artifacts/        Core build output grouped by platform
```

`src/` is intentionally reserved for the project's C++ implementation. Optional integrations, bindings, and third-party source live outside it. Core build artifacts are grouped under `build/artifacts/<platform>/`; dependency output remains under `build/deps/<platform>/`.
