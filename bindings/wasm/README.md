# WebAssembly build on Linux, macOS, and Windows

The default `createHybridCPABE` loader export preserves the raw Emscripten API.
The named `createHybridCpAbe` export adds the modern camelCase API; see the
[JavaScript SDK guide](../npm/README.md#modern-javascript--typescript-api-additive).
Keep `api.mjs` and `loader.d.mts` alongside the loader and runtime binaries.
Run `node tests/wasm/modern-api.mjs` after `make -f Makefile.wasm publish` to
exercise the modern API, buffer cleanup and legacy loader compatibility.

Builds the complete public C API: AC17, TKN20, CoverCrypt (including ML-KEM-768),
AES-GCM, ML-DSA-87, file/buffer operations, and the CLI entry point. Native DLL/SO
targets retain their existing toolchains and output paths.

Install CMake, GNU Make, Python 3, Node.js 18+, Go satisfying
`bindings/tkn20/go.mod`, and Emscripten SDK 7.0.0 or newer. Activate the SDK in the
current shell. Rust nightly with `rust-src` rebuilds the standard library against
the same Emscripten ABI as C++:

### Linux, WSL, and macOS

On macOS Intel and Apple Silicon, use the Emscripten SDK and Rust toolchain for
your host architecture. Install GNU Make 4 or newer. If you use Homebrew, put
GNU Make on `PATH` with `export PATH="$(brew --prefix make)/libexec/gnubin:$PATH"`.

```sh
source /path/to/emsdk/emsdk_env.sh
rustup toolchain install nightly --component rust-src
sh ./configure --wasm
make wasm -j8
make wasm-test -j8
```

### Windows x64 with MSYS2

Install Visual Studio C++ Build Tools with the Windows SDK for the Rust host.
Install Go, Emscripten SDK 7.0.0 or newer, and Rust via rustup. In the MSYS2
MINGW64 terminal, use the Windows Emscripten installation and put Windows Go
and Cargo on `PATH`. Replace the sample Emscripten path with your installation
directory.

```sh
export PATH="$(cygpath -u "$USERPROFILE")/.cargo/bin:/c/Program Files/Go/bin:$PATH"
source /c/path/to/emsdk/emsdk_env.sh
rustup toolchain install nightly-x86_64-pc-windows-msvc --component rust-src
sh ./configure --wasm --install  # Use --wasm alone when MSYS2 tools are installed
make wasm -j8
make wasm-test -j8
```

The Windows dependency build uses Ninja for liboqs. `--install` can provision
GNU Make, CMake, Ninja, and Python in MSYS2. The SDK, Go, and Rust are set up
separately. Run the Make commands in the same MSYS2 terminal.

### Build targets and outputs

Verified on Linux/WSL with Emscripten 7.0.0, Rust 1.99.0 nightly, Go 1.25.0 and
Node.js 18.19.1. Tests cover all three schemes through file/buffer APIs, policy
denial, ML-DSA signing/verification, and rejection of modified ciphertext.

From a repository checkout with a WASM build in `lib/wasm`, run the full Node.js
self-test directly:

```sh
node bindings/wasm/cli.mjs --test
```

This uses the same suite as `make wasm-test`. The suite exercises the public
C exports and uses WASM's in-memory filesystem for its test files.

Run `node bindings/wasm/cli.mjs --help` for file-based commands including setup,
key generation, encryption, and decryption. The
[npm CLI examples](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/npm#post-quantum-abe-from-the-cli)
also work from the repository when you replace `npx @wanthinnn/pq-cp-abe` with
`node /path/to/repo/bindings/wasm/cli.mjs`.

Standalone targets:

```sh
make -f Makefile.wasm -j8          # static archive + JS/WASM package
make -f Makefile.wasm deps JOBS=8 # build/check all dependencies
make -f Makefile.wasm static
make -f Makefile.wasm shared      # JS/WASM package
make -f Makefile.wasm executable  # same package, exposes callMain
make -f Makefile.wasm test
make -f Makefile.wasm clean
make -f Makefile.wasm clean-deps
```

`JOBS` controls dependency compiler jobs (default 8); `-j` controls C++ objects.
Normal builds reuse the dependency cache. Run `make wasm-deps` after dependency
source or toolchain changes. Build directories are selected by host:

| Host | Directory name under `build/deps/` and `build/artifacts/` |
| --- | --- |
| Linux and WSL | `wasm` |
| Windows MSYS2 | `wasm-windows` |
| macOS Intel | `wasm-macos-x86_64` |
| macOS Apple Silicon | `wasm-macos-arm64` |

Each build copies its deployment package to `lib/wasm`:

| File | Purpose |
| --- | --- |
| `loader.mjs` | Async factory initializing both runtimes |
| `hybrid-pq-cp-abe.mjs` | Emscripten module factory |
| `hybrid-pq-cp-abe.wasm` | C++/Rust/Crypto++/liboqs module |
| `tkn20.wasm` | CIRCL TKN20 with Go runtime |
| `wasm_exec.js` | Runtime support matching the Go compiler |
| `libhybrid-pq-cp-abe.a` | Merged archive for Emscripten C/C++ consumers |

Deploy the five runtime files together; the archive is for linking consumers.
See the [npm package guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/npm)
to package and test those runtime files for npm.
Import `loader.mjs` in Node.js or a browser
served over HTTP(S):

```js
import createHybridCPABE from './lib/wasm/loader.mjs';
const abe = await createHybridCPABE();
console.log(abe.ccall('getVersion', 'string', [], []));
abe.FS.mkdir('/keys');
const status = abe.ccall('setup_with_scheme', 'number',
  ['string', 'number'], ['/keys/demo', 1]); // 0=AC17, 1=TKN20, 2=CoverCrypt
if (status !== 0) throw new Error(`setup failed: ${status}`);
```

File APIs use Emscripten's in-memory filesystem. Transfer data using
`FS.writeFile`/`FS.readFile`; host paths are not mounted automatically. For
CoverCrypt, write the JSON configuration into that filesystem and set
`module.ENV.HCPABE_COVERCRYPT_CONFIG` in a `preRun` callback, or use the public
JSON buffer setup API. Release returned C buffers using `freeBuffer`.
Pointers and `size_t` are 32-bit. Run the CLI through
`abe.callMain(['version'])` after initialization.

TKN20 uses Go js/wasm instead of a native CGO archive. Its callback copies data
between Go and Emscripten memory. All schemes remain enabled. The static archive
also requires this runtime callback (`Module.tkn20`) in a consuming Emscripten
application; it is not a standalone WASI module. Loader instances share one Go
runtime. Rust panics abort the module; regular FFI error returns remain available.

References: [Go WebAssembly](https://go.dev/wiki/WebAssembly),
[Rust Emscripten ABI](https://doc.rust-lang.org/rustc/platform-support/wasm32-unknown-emscripten.html#emscripten-abi-compatibility).
