# Hybrid CP-ABE Dependencies Guide

This project relies on four core cryptographic libraries to function correctly. This guide provides step-by-step instructions on how to build and integrate each dependency natively on Windows (MSVC) and Linux (GCC).

---

## 1. liboqs (Open Quantum Safe)

Used for Post-Quantum Cryptography (PQC) signatures (e.g., ML-DSA). We explicitly disable OpenSSL dependencies (`-DOQS_USE_OPENSSL=OFF`) to keep the library lightweight and conflict-free.

### Prerequisites
- **CMake** (3.14 or later)
- **Windows:** Microsoft Visual Studio 2022 (with MSVC compiler v142/v143 installed)
- **Linux:** `build-essential` and `ninja-build`

### Windows (MSVC) Build
1. Open the **x64 Native Tools Command Prompt for VS 2022**.
2. Navigate to the `liboqs` source code folder.
3. Run the following commands:
```cmd
mkdir build_msvc
cd build_msvc
cmake -G "Ninja" -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF ..
cmake --build . --config Release
```
*Note: You can safely ignore any `fatal error LNK1120: unresolved externals` during the final test-linking phase. The core `oqs.dll` and `oqs.lib` files will have already been generated in `build_msvc\bin` and `build_msvc\lib`.*

### Linux (Ubuntu/WSL) Build
```bash
mkdir -p build_linux_static
cd build_linux_static
cmake -GNinja -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF ..
cmake --build .
```
The static library `liboqs.a` will be generated in `build_linux_static/lib/`.

---

## 2. libcpabe_tkn20 (TKN20 CP-ABE)

A C/C++ wrapper for the Ciphertext-Policy Attribute-Based Encryption (CP-ABE) scheme based on Cloudflare CIRCL. It is compiled using Go's CGO to generate a static library and a C header file.

### Prerequisites
- **Golang** (Version 1.18 or higher)
- **C Compiler:** MSVC/MinGW on Windows, `gcc` on Linux. Ensure `CGO_ENABLED=1`.

### Build Instructions
Navigate to the root directory containing `cpabe_tkn20.go` and run the appropriate command for your OS to build a static archive library.

**Windows:**
```powershell
go build -buildmode=c-archive -o libcpabe_tkn20.lib cpabe_tkn20.go
```

**Linux:**
```bash
go build -buildmode=c-archive -o libcpabe_tkn20.a cpabe_tkn20.go
```
This will generate the static library (`.lib` or `.a`) and the C header file (`libcpabe_tkn20.h`), which must be included in your project's `include` directory.

---

## 3. rabe-ffi (AC17 CP-ABE)

A C FFI binding for the Rust Attribute-Based Encryption library ([rabe](https://github.com/Fraunhofer-AISEC/rabe)).

### Prerequisites
- **Rust Toolchain:** Install via `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### Build Instructions
1. Set the default toolchain to nightly:
```bash
rustup default nightly
```
2. Clone and build the project:
```bash
git clone https://github.com/Aya0wind/Rabe-ffi.git
cd Rabe-ffi
cargo build --release
```
3. After building, copy the generated library (e.g., `target/release/librabe_ffi.a` or `.so`/`.lib`) to the `lib/static/` directory of your project, and copy the `rabe.h` header to your `include` directory.

---

## 4. Crypto++

A C++ class library of cryptographic algorithms. In this project, it is used for AES-GCM symmetric encryption and SHA3 hashing.

### Prerequisites
- GNU Make 3.81+ (Linux) or Visual Studio (Windows)

### Build Instructions (Linux)
You can build the static library directly from source:
```bash
make static
```
This will generate `libcryptopp.a`.

### Build using Vcpkg (Cross-Platform Alternative)
The easiest way to obtain Crypto++ on both Windows and Linux is via Microsoft's `vcpkg` dependency manager:
```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
./vcpkg install cryptopp:x64-windows  # Use x64-linux for Linux
```
After installation, locate the generated `cryptlib.lib` (Windows) or `libcryptopp.a` (Linux) in the `vcpkg/packages` directory and copy it to your project.
