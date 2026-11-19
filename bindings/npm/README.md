# Post-quantum CP-ABE for JavaScript

The WebAssembly bindings expose the library's C API from JavaScript. CoverCrypt
provides post-quantum attribute-based encryption with ML-KEM-768. AC17 and TKN20
are also available as classical schemes. The package includes the WASM binaries.
Calling the factory initializes both the Emscripten and Go runtimes.

## Quick start

```sh
npm install @wanthinnn/pq-cp-abe
```

Save this as `demo.mjs` and run `node demo.mjs` with Node.js 18 or newer.

```js
import createHybridCPABE from '@wanthinnn/pq-cp-abe';

const abe = await createHybridCPABE();
console.log(abe.ccall('getVersion', 'string', [], []));
```

The factory returns an Emscripten module with `ccall`, `FS` and `callMain`. See
the [WebAssembly guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/wasm)
for file operations and CoverCrypt configuration. See the
[public C API](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h)
for function signatures.

## Build and test the npm tarball

From the repository root on Linux, first [activate the WASM toolchain](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/wasm).

```sh
make wasm -j8
make wasm-test -j8
python3 scripts/package-release.py --wasm --version "$(cat VERSION)"
python3 bindings/npm/pack_release.py
```

The source `package.json` is a private template. The packer adds the version
from the root `VERSION` file to the staged manifest, installs the tarball in a
temporary Node.js project and runs the WASM smoke tests. The tested
tarball goes to `build/release/npm/` and can be installed with `npm install` using
its local path.

## Publish from GitHub Actions

Run [Build npm Package](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/actions/workflows/publish-npm.yml)
after the GitHub Release for the version in `VERSION` has the WASM ZIP and
`SHA256SUMS.txt`. With `publish=false`, the workflow verifies the ZIP, installs
and tests the tarball, then uploads the `npm-package` Actions artifact. With
`publish=true`, it also publishes that tested tarball to the public npm registry.

For a new package, publish the first tested tarball from the npm account that
owns the scope. Then configure [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/)
for this GitHub repository, the `publish-npm.yml` workflow and the `npm` GitHub
environment before using `publish=true`.
