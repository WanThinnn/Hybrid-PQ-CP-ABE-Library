---
icon: lucide/hammer
---

# Build from source

## Building (Multi-OS)
!!! important
    This library integrates the following cryptographic primitives and dependencies:

    - [CryptoPP Library](https://github.com/weidai11/cryptopp)
    - [CP-ABE AC17 Scheme](https://eprint.iacr.org/2017/807) (via [Rabe-ffi](https://github.com/WanThinnn/librabe-ffi.git))
    - [CP-ABE TKN20 Scheme](https://eprint.iacr.org/2019/966) (via [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/abe))
    - [Open Quantum Safe Library](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe - used for optional ML-DSA-87 signatures)
    - [HashiCorp Vault Secrets Engine](../../plugins/vault/README.md) (optional Go plugin for Enterprise Cryptography-as-a-Service)
    - [Cosmian CoverCrypt](https://eprint.iacr.org/2025/544) via [Cosmian CoverCrypt](https://github.com/Cosmian/cover_crypt) (native ABE integration with Classic, PostQuantum and Hybridized modes; see `vendor/cover_crypt/`)

!!! note
    **Dependency source of truth:** third-party source is vendored under `vendor/`. Built dependency headers and libraries are normalized under `build/deps/<platform>/`; the top level of that directory contains only `include/` and `lib/` after a successful dependency build.

For maintainer-only upstream Git histories and update commands, see
[vendor/README.md](../../vendor/README.md). Source stays vendored; ordinary clones do
not require submodule initialization.

### 1. Clone the repository

```sh
git clone https://github.com/WanThinnn/Hybrid-PQ-CP-ABE.git
cd Hybrid-PQ-CP-ABE
```

Required toolchains include CMake, Rust/Cargo, GNU Make, and a native C/C++
compiler with C++17 support (the default native build standard). Use the Go version declared in [the TKN20 module](../../bindings/tkn20/go.mod)
and check [the Vault module](../../plugins/vault/vault-plugin-abe/go.mod) when
building the plugin. Windows also requires the MSVC x64 build tools and
MinGW-w64 `gcc` for Go CGO/TKN20.

The root `VERSION` file is the version source of truth. Make generates the public
`include/hybrid_pq_cp_abe/version.h` header and embeds that value in the library
and CLI. Changing `VERSION` triggers an incremental rebuild; deployed binaries
do not need to find a `VERSION` file at runtime.

### 2. Configure a new machine

The single `configure` file checks the host toolchain without installing or
downloading anything. Missing tools produce a nonzero exit status. Use
`--install` explicitly to install missing tools; OS installers may request
administrator access or interactive completion.

#### **Linux / macOS**

Run these commands in a **Unix shell** from the repository root. No Make or
Python installation is needed to start the check:

```sh
chmod +x configure
./configure
./configure --install
. ./build/tools/activate.sh
```

For a custom Linux/macOS toolchain with an explicitly controlled `PATH`, use
`HCPABE_CONFIGURE_DISCOVER_PATHS=0 ./configure`. This disables automatic search
paths for bundled Go, Cargo and Homebrew; ordinary checks retain discovery by
default. Configure tests use this mode so runner-installed tools cannot hide
the missing/old tool versions being tested.

Linux installation supports apt, dnf, pacman and zypper. Go is downloaded from
the official Go release metadata with SHA256 verification when needed. macOS
uses Apple Command Line Tools and Homebrew; finish any Apple installer dialog
and rerun `configure --install` if prompted. Rust uses the official rustup
installer. **Run subsequent `make` commands in the same activated shell.**
Activation adds local tools to this shell's PATH.

#### **Windows**

**Prerequisite: install the Microsoft C++ build tools and use an x64 Native
Tools Command Prompt for all native `make` commands.**

1. Download **Build Tools for Visual Studio** or Visual Studio from the
    [official Microsoft downloads page](https://visualstudio.microsoft.com/downloads/).
    In Visual Studio Installer, select **Desktop development with C++**, including
    the **MSVC x64/x86 build tools** and a **Windows SDK**. If these components
    are already installed, keep your existing installation. See
    [Microsoft's command-line setup guide](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line)
    for details.

2. Open the **Start menu**, search for **x64 Native Tools Command Prompt**,
    and open the shortcut for your installed Visual Studio version
    (for example, **x64 Native Tools Command Prompt for VS 2022** or **VS 2026**).
    **Use this one cmd session for setup, activation, build and tests.**

3. From that **x64 cmd**, enter your repository directory:

    ```cmd
    cd /d D:\path\to\Hybrid-PQ-CP-ABE
    ```

    **Check only** — report missing tools without installing or generating an
    activation script:

    ```cmd
    powershell.exe -NoProfile -Command ^
        "$text = Get-Content .\configure -Raw;" ^
        "$setup = [scriptblock]::Create(($text -split '(?m)^# WINDOWS CONFIGURE\r?$', 2)[1]);" ^
        "& $setup"
    ```

    **Install missing tools and generate activation** — use this for first-time
    setup, even if the check reports that all tools are already installed:

    ```cmd
    powershell.exe -NoProfile -Command ^
        "$text = Get-Content .\configure -Raw;" ^
        "$setup = [scriptblock]::Create(($text -split '(?m)^# WINDOWS CONFIGURE\r?$', 2)[1]);" ^
        "& $setup -Install"
    ```

    Both commands run PowerShell as a child process and return to the same cmd.
    The `^` characters continue the command across lines in cmd; copy the whole
    block. The install command uses WinGet and MSYS2's package manager for
    MSYS2/Make/CMake/MinGW, Go and Rust. If WinGet is missing, install
    [Microsoft App Installer](https://aka.ms/getwinget) first.

    **Activate after successful setup**, in the same cmd:

    ```cmd
    call build\tools\activate.cmd
    ```

    Run activation in each new build session. It adds Windows system utilities,
    MSYS2/Make, Go and Rust to `PATH` and prepares MSVC x64. The MSYS2 location
    comes from configure (`MSYS2_ROOT`, or `C:\msys64` by default).

    To verify linker priority:

    ```cmd
    where.exe cl.exe
    where.exe link.exe
    ```

    **The first `link.exe` result must be the MSVC linker under your Visual Studio
    installation.** Activation preserves existing MSVC tool paths ahead of MSYS2.

**Continue with steps 3–5 below in this same activated x64 cmd session.**

**WebAssembly (both platforms):** On Linux, WSL, macOS, or Windows MSYS2, use
`sh ./configure --wasm` after activating Emscripten to check the WebAssembly
toolchain. Combine it with `--install` to install the standard host tools. See
the [WebAssembly guide](../../bindings/wasm/README.md) for platform setup.

### 3. Build native dependencies

```sh
make deps -j8
```
This builds Crypto++, liboqs, librabe-ffi, CIRCL/TKN20, and CoverCrypt. liboqs is configured as a minimal ML-KEM + ML-DSA build only: ML-KEM-512/768/1024 and ML-DSA-44/65/87. The `-jN` budget is distributed across the five dependency builds without oversubscribing the requested total.

**Dependency output**

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

### 4. Build the Hybrid-CP-ABE native core

```sh
make -j8
```
The core consumes headers and libraries directly from `build/deps/<platform>/`. After a successful dependency build, `build/deps/<platform>/lib/.ready` marks the dependency set as ready; normal `make -jN` builds do not run the dependency scripts again and go straight to the native core.

### 5. Run tests

```sh
make test -j8
```

On Windows, run these commands in the **x64 Native Tools Command Prompt**
prepared in step 2. Windows uses the MSVC x64 ABI; `librabe-ffi` is forced to `x86_64-pc-windows-msvc`, while TKN20 uses Go/MinGW only behind a C ABI DLL plus an MSVC import `.lib`.

The native C++ library, Crypto++, and liboqs use the dynamic MSVC runtime (`/MD`). Crypto++ still links as a static `.lib`. The dependency builder removes byte-identical duplicate archive members from the Rust static library while preserving its symbols and COFF linker indexes.

After `make`, the build prints the exact include, dependency-library, native-library, shared-library, runtime-DLL, and CLI output paths. `include/` and `lib/` at the repository root are project-only: `include/hybrid_pq_cp_abe/` contains the public Hybrid-CP-ABE API, while `lib/` contains the project static and shared libraries side by side. All third-party headers/libraries stay exclusively under `build/deps/<platform>/`.

Normal core builds are incremental. Use `make clean` only to remove the project core/object output. Use `make clean-deps` to remove the complete dependency output for the current platform.

### Choose the C++ standard

The native Makefile defaults to `CXX_STANDARD ?= c++17`. Override it on the
command line or through the environment to select a standard supported by your
compiler. For example, to build and test with C++20 on Linux, macOS, or Windows:

```sh
make clean
make -j8 CXX_STANDARD=c++20
make test -j8 CXX_STANDARD=c++20
```

Pass the same value to each build and test invocation. Run `make clean` when
changing standards because Make does not track compiler flag changes; existing
objects would otherwise be reused. This only requires rebuilding the native core,
so you can keep the staged dependencies.

`CXX_STANDARD` supplies `-std=c++20` to GCC/Clang or `/std:c++20` to MSVC in
the example above. It controls the native core, CLI, and C++ tests; dependency
and WebAssembly builds use their own settings. Prefer this variable when changing
only the standard: setting `CXXFLAGS` on the Make command line replaces the
complete default flag list, including include paths and optimization flags.

The C header compatibility check in `make test` compiles `crypto_params.c` as C
and filters C++ standard flags from that command. Choosing C++17, C++20, or
another C++ standard therefore does not pass an incompatible C++ flag to the C
compiler mode.

See [build/README.md](../../build/README.md) for the output layout. Keep logs under
`build/logs/`, local reports under `build/reports/`, and temporary fixtures under
`build/tmp/`. Reusable diagnostic scripts live in `scripts/diagnostics/`.

### Available Make Commands

- `make deps -j8`: Build/check the five native dependencies and print their final include/library layout.
- `make -j8`: Build the native C++ core directly from the existing dependency output. It only auto-builds dependencies when the ready marker is missing (fresh clone or after `make clean-deps`).
- `make clean-deps`: Remove `build/deps/<platform>/`.
- `make static`: Build only the project static library.
- `make shared`: Build only the project shared library.
- `make executable`: Build only the CLI executable.
- `make test -j8`: Incrementally build and run the tests.
- `make tests -j8`: Alias for `make test -j8`.
- `make install`: Install the CLI, public headers, and native static/shared libraries to the system. On Windows, the default prefix is `%LOCALAPPDATA%\Programs\pq-cp-abe` with `bin/`, `include/`, and `lib/` subdirectories.
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
