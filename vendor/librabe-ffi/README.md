# Rabe-ffi

C FFI binding for the [rabe](https://github.com/Fraunhofer-AISEC/rabe) Rust Attribute-Based Encryption library.
It supports both CP-ABE (Ciphertext-Policy) and KP-ABE (Key-Policy) encryption and decryption schemes, including AC17, BSW, AW11, BDABE, MKE08, LSW, and YCT14.

This library is fully updated to `rabe 0.4.x` (which includes AEAD authenticated encryption) and contains strict memory-safety fixes for robust production use.

## Prerequisites

Regardless of your operating system, the build process requires:

1. **Rust Toolchain (nightly)**: Required because the build script uses `cbindgen`'s `with_parse_expand` feature to generate C headers from macros.
2. **`cargo-expand`**: Required by `cbindgen` to expand Rust macros before generating the C header.
3. **C/C++ Build Tools**: MSVC on Windows, GCC/Clang on Linux/macOS.

First, install Rust via [rustup](https://rustup.rs/), then set up the nightly toolchain and install `cargo-expand`:

```bash
rustup default nightly
cargo install cargo-expand
```

## Build Instructions

### Linux

1. Install build essentials:
   ```bash
   # Debian / Ubuntu
   sudo apt update && sudo apt install build-essential
   
   # Fedora / RHEL
   sudo dnf groupinstall "Development Tools"
   ```
2. Clone and build:
   ```bash
   git clone https://github.com/WanThinnn/librabe-ffi.git
   cd librabe-ffi
   cargo build --release
   ```
3. **Output**: You will find `librabe_ffi.so` (dynamic library), `librabe_ffi.a` (static library) in `target/release/`, and `rabe.h` (C header) in the project root.

### macOS

1. Install Xcode Command Line Tools:
   ```bash
   xcode-select --install
   ```
2. Clone and build:
   ```bash
   git clone https://github.com/WanThinnn/librabe-ffi.git
   cd librabe-ffi
   cargo build --release
   ```
3. **Output**: You will find `librabe_ffi.dylib` (dynamic library), `librabe_ffi.a` (static library) in `target/release/`, and `rabe.h` in the project root.

### Windows (MSVC)

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/). Ensure you select **Desktop development with C++** during installation.
2. Make sure you install Rust using PowerShell or CMD (do **not** use MSYS2/Git Bash to avoid mixing toolchains).
3. Clone and build:
   ```powershell
   git clone https://github.com/WanThinnn/librabe-ffi.git
   cd librabe-ffi
   cargo build --release
   ```
4. **Output**: You will find `rabe_ffi.dll` (dynamic library), `rabe_ffi.dll.lib` (import library), `rabe_ffi.lib` (static library) in `target\release\`, and `rabe.h` in the project root.

## Integration into C/C++ Projects

1. Copy the dynamic library (`.so`, `.dylib`, or `.dll`) to your project directory or system library path. On Windows, you also need the `.dll.lib` file for linking.
2. Copy `rabe.h` to your project's include directory.
3. Include the header and link the library during compilation.

Example (AC17 scheme):

```c
#include "rabe.h"

int main() {
    Ac17SetupResult keys = rabe_ac17_init();
    
    // ... use keys.public_key, keys.master_key ...
    
    rabe_ac17_free_public_key(keys.public_key);
    rabe_ac17_free_master_key(keys.master_key);
    return 0;
}
```

*Note: For detailed usage of other schemes, refer to the unit tests in the Rust source code (`src/cp_abe/` and `src/kp_abe/`).*
