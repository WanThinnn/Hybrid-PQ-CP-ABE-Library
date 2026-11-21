# WebAssembly build on Linux, macOS, and Windows

Initialize `PqCpAbe` or a scheme class with its asynchronous `.create()` method.
Use `instance.api` for functional methods, including file operations in WASM.
The default Emscripten factory is available for compatibility. [JavaScript SDK guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/npm#functional-javascript-and-typescript-api)

The build includes AC17, TKN20, CoverCrypt, parameterized AES-GCM, ML-DSA and
standalone ML-KEM, and the CLI entry point.

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

The bundled command runs the compatibility self-test in WASM's in-memory
filesystem. `make wasm-test` also checks all public export names, the functional
and object APIs, and the 6.1 CLI.

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

Deploy the JavaScript modules and WASM files together, keeping the `lib/wasm`
subdirectories from the build. The static archive serves C/C++ linking.
Import `loader.mjs` from Node.js or a browser served over HTTP(S). [npm package guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/npm)

```js
import { PqCpAbe, Scheme } from './lib/wasm/loader.mjs';

const { api } = await PqCpAbe.create();
console.log(api.getVersion());
api.native.FS.mkdir('/keys');
api.setupFiles({ outputPath: '/keys/demo', scheme: Scheme.TKN20 });
```

File APIs use Emscripten's in-memory filesystem. Transfer data with
`api.native.FS.writeFile` and `api.native.FS.readFile`. For CoverCrypt in memory,
pass `config` to `CoverCryptABE.create` or call `api.covercryptSetup` with JSON.
For CoverCrypt file setup, write the JSON to the WASM filesystem and set
`module.ENV.HCPABE_COVERCRYPT_CONFIG` in a `preRun` callback.

TKN20 uses Go js/wasm instead of a native CGO archive. Its callback copies data
between Go and Emscripten memory. All schemes remain enabled. The static archive
also requires this runtime callback (`Module.tkn20`) in a consuming Emscripten
application; it is not a standalone WASI module. Loader instances share one Go
runtime. Rust panics abort the module; regular FFI error returns remain available.

References: [Go WebAssembly](https://go.dev/wiki/WebAssembly),
[Rust Emscripten ABI](https://doc.rust-lang.org/rustc/platform-support/wasm32-unknown-emscripten.html#emscripten-abi-compatibility).
