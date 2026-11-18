# WebAssembly build on Linux

Builds the complete public C API: AC17, TKN20, CoverCrypt (including ML-KEM-768),
AES-GCM, ML-DSA-87, file/buffer operations, and the CLI entry point. Native DLL/SO
targets retain their existing toolchains and output paths.

Install CMake, GNU Make, Python 3, Node.js 18+, Go satisfying
`bindings/tkn20/go.mod`, and Emscripten SDK 7.0.0 or newer. Activate the SDK in the
current shell. Rust nightly with `rust-src` rebuilds the standard library against
the same Emscripten ABI as C++:

```sh
source /path/to/emsdk/emsdk_env.sh
rustup toolchain install nightly --component rust-src
make wasm -j8
make wasm-test -j8
```

Verified on Linux/WSL with Emscripten 7.0.0, Rust 1.99.0 nightly, Go 1.25.0 and
Node.js 18.19.1. Tests cover all three schemes through file/buffer APIs, policy
denial, ML-DSA signing/verification, and rejection of modified ciphertext.

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
Dependencies use `build/deps/wasm/{include,lib}`. Normal builds reuse the ready
marker; run `make wasm-deps` after dependency source/toolchain changes. Checks
fingerprint source contents and compiler versions. Objects, the merged static
archive, and modules go to `build/artifacts/wasm`. The deployment package is
copied to `lib/wasm`:

| File | Purpose |
| --- | --- |
| `loader.mjs` | Async factory initializing both runtimes |
| `hybrid-pq-cp-abe.mjs` | Emscripten module factory |
| `hybrid-pq-cp-abe.wasm` | C++/Rust/Crypto++/liboqs module |
| `tkn20.wasm` | CIRCL TKN20 with Go runtime |
| `wasm_exec.js` | Runtime support matching the Go compiler |
| `libhybrid-pq-cp-abe.a` | Merged archive for Emscripten C/C++ consumers |

Deploy the five runtime files together; the archive is for linking consumers.
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
