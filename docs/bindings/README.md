# Language bindings

The repository provides two primary developer SDKs. The native library and command-line tool have their own [build guide](../build.md) and [CLI reference](../cli.md).

| SDK | Runtime | Start here | API reference |
| --- | --- | --- | --- |
| Python | Native shared library via `ctypes` (Windows DLL, Linux SO, macOS DYLIB) | [Python guide](python/README.md) | [Python API](python/api.md) |
| JavaScript / TypeScript | WebAssembly (Emscripten C++/Rust + Go TKN20 runtime), in Node.js and browsers | [WASM guide](wasm/README.md) | [JavaScript API](wasm/api.md) |

- Python package: [`pq-cp-abe` on PyPI](https://pypi.org/project/pq-cp-abe/).
- JavaScript package: [`@wanthinnn/pq-cp-abe` on npm](https://www.npmjs.com/package/@wanthinnn/pq-cp-abe).
- [Architecture and cryptographic modes](../architecture.md) · [Parameters and wire format](../native_parameters.md).

**Security boundary:** AC17 and TKN20 are classical ABE schemes. CoverCrypt supports ML-KEM-768 in `HYBRIDIZED` and `POST_QUANTUM` modes. Optional ML-DSA signing is independent and does not turn classical ABE into quantum-resistant ABE.
