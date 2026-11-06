# Hybrid PQ-CP-ABE Library
Hybrid Post-Quantum Ciphertext-Policy Attribute-Based Encryption Library for C/C++ in Windows/Linux


> [!NOTE]
> This library provides two distinct PQC capabilities: optional **ML-DSA-87**
> signatures in the Sign-then-Encrypt flow through `liboqs`, and native
> **CoverCrypt** key encapsulation with **ML-KEM-768** in `hybridized` or
> `post_quantum` mode. ML-DSA-87 signatures alone do not make AC17 or TKN20
> quantum-resistant.

> [!IMPORTANT]
> AC17 and TKN20 remain classical pairing-based ABE. CoverCrypt uses
> Curve25519 + ML-KEM-768 by default (`hybridized` mode), or can be configured
> for `post_quantum` or `classic` mode. ML-DSA-87 signing is optional and
> independent of the CoverCrypt mode. Historical v5.2 benchmark results below
> describe AC17/TKN20 only.

## Native interface and source layout

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

For a quick CLI smoke test, use the checked-in [scripts/covercrypt-demo.json](scripts/covercrypt-demo.json)
with `Department::{IT,HR}` and `Level::{USER,ADMIN}`. Run `main --help` for CMD,
PowerShell and Linux/macOS environment commands and a setup/keygen/encrypt/decrypt
example. The demo contains only attribute definitions, not keys. Setup requires
`HCPABE_COVERCRYPT_CONFIG`; the CLI does not automatically read `.env` files.

### Native PQC with CoverCrypt

CoverCrypt's native PQC mode protects the ABE key-encapsulation path with
ML-KEM-768. It does not require the `--pqc` signing option. For example, on
Linux/macOS:

```sh
export HCPABE_COVERCRYPT_CONFIG=scripts/covercrypt-demo.json
export HCPABE_COVERCRYPT_MODE=hybridized
mkdir -p keys
build/artifacts/linux/main setup --scheme covercrypt ./keys/demo
build/artifacts/linux/main genkey --scheme covercrypt ./keys/demo_msk.key "Department::IT Level::ADMIN" ./keys/user.key
```

Use `post_quantum` to select CoverCrypt's post-quantum mode or `classic` for
its classical mode. The default is `hybridized`. The optional `--pqc` flag is
a separate feature: it adds ML-DSA-87 signing/verification to the
Sign-then-Encrypt flow for any scheme. AC17 and TKN20 remain classical ABE
schemes regardless of that flag.

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
build/artifacts/windows/main.exe add_dimension --scheme covercrypt ./keys/demo_msk.key scripts/covercrypt-add-e.json ./keys/demo-v2
```

On Linux/macOS, use `build/artifacts/linux/main` or
`build/artifacts/macos/main` respectively. `scripts/covercrypt-add-e.json` is one
dimension object, whereas the setup JSON contains a `dimensions` array.

For a new value in an existing dimension:

```sh
build/artifacts/windows/main.exe add_attribute --scheme covercrypt ./keys/demo-v2_msk.key Department SALES ./keys/demo-v3
```

For hierarchical dimensions, the optional final argument is the existing
attribute after which the new value is inserted; without it, upstream assigns
the lowest rank. `HCPABE_COVERCRYPT_MODE` controls only the new attributes.

Retain **both** updated master keys and use the updated MSK for subsequent
`genkey` operations. Old user keys retain their previous rights on old and new
ciphertexts using those rights. They do not automatically gain E. Grant E by
issuing a new authorized key from the updated MSK, for example:

```sh
build/artifacts/windows/main.exe genkey --scheme covercrypt ./keys/demo-v2_msk.key "Department::IT && Level::ADMIN && E::present" ./keys/user-e.key
```

Signing keys are unchanged and can be reused. Omit `--pqc` on growth commands.
Serialize authority-management operations and review the new pair before
switching applications to it. Output files must not already exist.

This follows upstream's [update_msk](https://docs.rs/cosmian_cover_crypt/latest/cosmian_cover_crypt/struct.Covercrypt.html#method.update_msk)
and [AccessStructure](https://docs.rs/cosmian_cover_crypt/latest/cosmian_cover_crypt/struct.AccessStructure.html)
APIs. Adding rights differs from `rekey` (rotate secrets), `refresh_usk` (refresh
an existing key's revisions), or `prune_master_secret_key` (irreversibly remove
old revisions). Growth does not revoke previously issued keys.

## Performance & Benchmarks

The library uses a **hybrid KEM/DEM-style architecture**: ABE protects a
randomly generated secret under the access policy, SHA3-256 derives the
AES-256 key, and AES-GCM handles the bulk payload. CoverCrypt's `hybridized`
or `post_quantum` mode uses ML-KEM-768 in the ABE encapsulation path.
Separately, the optional `--pqc` path adds **ML-DSA-87 Sign-then-Encrypt**
before the payload enters the hybrid encryption pipeline.

For the current binary format, AES-GCM authenticates the header as AAD:

`[Version | Scheme | IV | Encapsulated-Key Length | Encapsulated CP-ABE Key]`

The ML-DSA-87 layer signs:

`[PolicyLen | Policy | Plaintext]`

before encryption.

### Published Benchmark Snapshot

A reproducible v6.0.0 benchmark snapshot is published under
[`benchmark/published/2026-11-01_i5-12450HX_standard/`](benchmark/published/2026-11-01_i5-12450HX_standard/).

Benchmark environment:

- **CPU:** Intel Core i5-12450HX
- **OS:** Windows 10
- **Library:** v6.0.0
- **Profile:** Standard
- **Timed iterations:** 100 after 5 warm-up iterations
- **Payload:** 4 KiB
- **Policy:** 12 terms; CoverCrypt uses 4 dimensions in Hybridized mode
- **Primary metric:** Median latency
- **Outlier policy:** No samples removed

Native Buffer API median latency:

<p align="center">
  <img src="benchmark/published/2026-11-01_i5-12450HX_standard/charts/01_core_latency.png" alt="Native AC17, TKN20 and CoverCrypt core latency" width="900"/>
</p>

| Scheme | Setup | KeyGen | Encrypt | Decrypt |
| --- | ---: | ---: | ---: | ---: |
| **AC17 Buffer** | 27.184 ms | 146.720 ms | 155.622 ms | 39.902 ms |
| **TKN20 Buffer** | **10.639 ms** | 248.388 ms | 110.973 ms | **32.720 ms** |
| **CoverCrypt Buffer** | 34.372 ms | **1.101 ms** | **12.529 ms** | 92.342 ms |

These are 4 KiB payload measurements. CoverCrypt ran in Hybridized mode
(Curve25519 + ML-KEM-768); its 12-term policy spans four dimensions, with OR
within each dimension and AND between dimensions.

The primitive comparison measures protection and recovery of 32-byte key
material. Charm-Crypto AC17 is included as a GT-element reference, not as a
byte-for-byte equivalent:

| Implementation | Setup | KeyGen | Protect | Recover |
| --- | ---: | ---: | ---: | ---: |
| **AC17** | 23.650 ms | 148.970 ms | 147.055 ms | 36.620 ms |
| **TKN20** | **8.071 ms** | 253.420 ms | 114.548 ms | **29.901 ms** |
| **CoverCrypt** | 40.511 ms | **1.921 ms** | **18.991 ms** | 72.000 ms |
| **Charm-Crypto AC17** | 85.063 ms | 204.176 ms | 142.135 ms | 293.191 ms |

<p align="center">
  <img src="benchmark/published/2026-11-01_i5-12450HX_standard/charts/00_abe_primitive_comparison.png" alt="ABE key-protection primitive comparison" width="900"/>
</p>

### Post-Quantum Signature Cost

ML-DSA-87 primitive measurements for a 4 KiB message:

| Operation | Median |
| --- | ---: |
| KeyGen | 0.552 ms |
| Sign | 1.135 ms |
| Verify | 0.644 ms |

The benchmark also measures the end-to-end ML-DSA-87 Sign-then-Encrypt path.
Those timings include the ABE and payload operations, so they should not be
interpreted as isolated signature cost. See the snapshot report for per-scheme
results and variability.

<p align="center">
  <img src="benchmark/published/2026-11-01_i5-12450HX_standard/charts/03_pqc_overhead.png" alt="ML-DSA-87 Sign-then-Encrypt overhead by scheme" width="900"/>
</p>

### Reproducibility

The published snapshot includes:

- [`report.md`](benchmark/published/2026-11-01_i5-12450HX_standard/report.md) — methodology, environment, results, and interpretation notes.
- [`summary.csv`](benchmark/published/2026-11-01_i5-12450HX_standard/summary.csv) — median, mean, p95, p99, standard deviation, and coefficient of variation.
- [`raw_samples.csv`](benchmark/published/2026-11-01_i5-12450HX_standard/raw_samples.csv) — every recorded timing sample.
- [`benchmark_results.json`](benchmark/published/2026-11-01_i5-12450HX_standard/benchmark_results.json) — machine-readable results and benchmark metadata.
- [`charts/`](benchmark/published/2026-11-01_i5-12450HX_standard/charts/) — generated benchmark figures.
- [`benchmark/`](benchmark/) — scripts and instructions required to reproduce the tests.

> [!IMPORTANT]
> **Benchmark comparison scope:** native AC17/TKN20 use the in-memory Buffer
> API and byte-oriented hybrid pipeline. CoverCrypt uses its shared KEM secret
> with AES-GCM to wrap key material. Charm-Crypto AC17 operates on a GT group
> element, so it is a reference rather than a strict equivalent. Results are
> specific to this machine and workload, not universal speedup claims.

> [!NOTE]
> This library provides native C/C++ integrations for **AC17**, **TKN20**, and
> **CoverCrypt**. For projects that need a broader research-oriented collection
> of cryptographic schemes such as KP-ABE or IBE, [Charm-Crypto](https://github.com/JHUISI/charm) remains a broader framework.

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

## Building (Multi-OS)
> [!IMPORTANT]
> This library integrates the following cryptographic primitives and dependencies:
- [CryptoPP Library](https://github.com/weidai11/cryptopp)
- [CP-ABE AC17 Scheme](https://eprint.iacr.org/2017/807) (via [Rabe-ffi](https://github.com/WanThinnn/librabe-ffi.git))
- [CP-ABE TKN20 Scheme](https://eprint.iacr.org/2020/733) (via [Cloudflare CIRCL](https://github.com/cloudflare/circl/tree/main/abe))
- [Open Quantum Safe Library](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe - used for optional ML-DSA-87 signatures)
- [HashiCorp Vault Secrets Engine](plugins/vault/README.md) (optional Go plugin for Enterprise Cryptography-as-a-Service)
- [Cosmian CoverCrypt](https://github.com/Cosmian/cover_crypt) (native ABE integration with Classic, PostQuantum and Hybridized modes; see `vendor/cover_crypt/`)

> [!NOTE]
>
> **Dependency source of truth:** third-party source is vendored under `vendor/`. Built dependency headers and libraries are normalized under `build/deps/<platform>/`; the top level of that directory contains only `include/` and `lib/` after a successful dependency build.

For maintainer-only upstream Git histories and update commands, see
[vendor/README.md](vendor/README.md). Source stays vendored; ordinary clones do
not require submodule initialization.

1. Clone the repository:
    ```sh
    git clone https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library.git
    cd Hybrid-PQ-CP-ABE-Library
    ```

Required toolchains: CMake, Rust/Cargo, Go 1.24+, GNU Make, and a native C/C++ compiler. Windows additionally requires Visual Studio 2022/MSVC and MinGW-w64 `gcc` for Go CGO/TKN20.

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

See [build/README.md](build/README.md) for the output layout. Keep logs under
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

## Usage

### Using the Executable



The usage of the executable is as follows:
```sh
Usage: main [command] [--scheme <name>] [--pqc] [options]
Usage: main setup [--scheme <name>] <path_to_save_file>
Usage: main genkey [--scheme <name>] <master_key_file> <attributes> <private_key_file>
Usage: main encrypt [--scheme <name>] <public_key_file> [pqc_private_key] <plaintext_file> <policy> <ciphertext_file>
Usage: main decrypt <private_key_file> [pqc_public_key] <ciphertext_file> <recovertext_file>
```

Example commands (Standard Mode):
```sh
main setup --scheme tkn20 test_case
main genkey --scheme tkn20 "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
main encrypt --scheme tkn20 "test_case/cpabe_pk.key" "test_case/plaintext.txt" "((A and C) or E)" "test_case/ciphertext.txt"
main decrypt "test_case/cpabe_sk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```

Example commands (Optional ML-DSA-87 Signatures):

The `--pqc` option enables ML-DSA-87 Sign-then-Encrypt signatures; it does not
change the ABE scheme's confidentiality properties. AC17 and TKN20 remain
classical. To use native post-quantum key encapsulation, select CoverCrypt and
set `HCPABE_COVERCRYPT_MODE` to `hybridized` (default) or `post_quantum` as
described above.

```sh
main setup --scheme tkn20 --pqc test_case
main genkey --scheme tkn20 "test_case/cpabe_msk.key" "A B C" "test_case/cpabe_sk.key"
main encrypt --scheme tkn20 --pqc "test_case/cpabe_pk.key" "test_case/pqc_sk.key" "test_case/plaintext.txt" "\"A\"" "test_case/ciphertext.txt"
main decrypt --pqc "test_case/cpabe_sk.key" "test_case/pqc_pk.key" "test_case/ciphertext.txt" "test_case/recovertext.txt"
```
### Integrating the Library
After building the library, you can integrate it into any program on Windows/Linux. Here are the steps to include the library in your project.
See [`bindings/python/`](bindings/python/) for the Python binding.

### HashiCorp Vault Plugin
This library natively provides a **HashiCorp Vault Custom Secrets Engine** written in Go (using Cgo to wrap the C++ core). It enables you to run a true "Cryptography-as-a-Service" architecture where the Master Secret Key (MSK) never leaves the Vault enclave.
- Exposes RESTful APIs: `/v1/abe/setup`, `/v1/abe/genkey`, `/v1/abe/encrypt`, `/v1/abe/decrypt`.
- Multi-stage Docker environments for seamless building and testing.
See [`plugins/vault/README.md`](plugins/vault/README.md) and [`plugins/vault/TESTING.md`](plugins/vault/TESTING.md) for build, test, and deployment instructions.

## Acknowledgements
Special thanks to [Aya0wind](https://github.com/Aya0wind) for Rabe-ffi, [Cloudflare](https://github.com/cloudflare/circl) for CIRCL TKN20, [Open Quantum Safe](https://github.com/open-quantum-safe) for `liboqs`, [CryptoPP](https://github.com/weidai11/cryptopp), and [Cosmian](https://github.com/Cosmian/cover_crypt) for CoverCrypt. CoverCrypt attribution and its BUSL-1.1 license are retained in `vendor/cover_crypt/`.
## GitHub releases

Pushing a `v*` tag or publishing a GitHub Release builds and tests Windows x64
(MSVC), Linux x86_64, macOS Intel, and macOS Apple Silicon on native runners.
All four native SDK ZIPs, the Linux Vault ZIP and `SHA256SUMS.txt` are attached only after every build
and package check succeeds. Running the workflow manually builds downloadable
Actions artifacts without publishing a release. Packages include the CLI,
static/shared libraries, headers, dependency libraries, and license notices.

The workflow must be committed before creating the tag/release. Historical
prebuilt files tracked by Git LFS are not used. Use
`./scripts/release.sh 6.0.0 --dry-run` to preview the native and Linux Vault packages.
After committing the release changes, `./scripts/release.sh 6.0.0` checks the
root `VERSION` file and release notes, asks before pushing, then pushes the branch and tag.
The public version header is generated during builds and need not exist when tagging.
By default it refuses to replace an existing tag. To retry an unpublished release
after fixing CI, run `./scripts/release.sh 6.0.0 --replace-tag`. After confirmation,
it pushes the branch, removes the existing tag from origin and locally, then
creates and pushes a new tag at the current commit. Remote deletion stops if the
tag changed since preflight. Use `--replace-tag --dry-run` to preview without changes.
For releases already distributed to users, publish a new version instead.
The helper always releases all four targets and does not accept per-platform flags.

## License

Original project code is licensed under the [Apache License, Version 2.0](LICENSE).
Copyright 2026 Thien Lai. See [NOTICE](NOTICE) for attribution and license scope.

Unless explicitly stated otherwise, contributions intentionally submitted for inclusion in the original project code are provided under the Apache License, Version 2.0.

Third-party code under `vendor/` retains its original license. In particular, `vendor/cover_crypt/` is governed by its bundled BUSL-1.1 license; see `vendor/cover_crypt/LICENSE.md` and `vendor/cover_crypt/UPSTREAM.md`.
