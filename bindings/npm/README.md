# PQ-CP-ABE for JavaScript and TypeScript

WebAssembly-based Ciphertext-Policy Attribute-Based Encryption SDK with post-quantum cryptography support for **Node.js and browsers**. It combines AC17, TKN20, or CoverCrypt with AES-GCM and optional ML-DSA digital signatures. CoverCrypt supports ML-KEM-768 for key encapsulation; AC17 and TKN20 remain classical ABE.

~~~sh
npm install @wanthinnn/pq-cp-abe
~~~

**Documentation:** [WASM SDK guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/wasm/README.md) · [API reference](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/wasm/api.md) · [CLI and build](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/wasm/cli.md).

## Quick start

Initialize the WASM runtime asynchronously; encryption and decryption methods run synchronously after initialization.

~~~js
import { PqCpAbe, KemMode } from '@wanthinnn/pq-cp-abe';

const abe = await PqCpAbe.create({
  config: { dimensions: [{ name: 'department', attributes: ['finance', 'it'] }] },
  mode: KemMode.HYBRIDIZED,
});

console.log(abe.api.getVersion());
~~~

`PqCpAbe` defaults to CoverCrypt. Its object API provides `setup()`, `keygen()`, `encrypt()` and `decrypt()`, plus `setupWithSigning()`, `encryptAndSign()` and `decryptAndVerify()` for optional ML-DSA signing. Pass `scheme` to select AC17 or TKN20. See the [API guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/wasm/api.md) for complete methods and examples.

## SDK surface

| Export | Purpose |
| --- | --- |
| `PqCpAbe`, `AC17CPABE`, `TKN20CPABE`, `CoverCryptABE` | Typed object interface for ABE |
| `createHybridCpAbe()` / `createPqCpAbe()` | Functional API |
| `AesGcm`, `MlDsa`, `MlKem` | Standalone cryptographic primitives |
| `Scheme`, `KemMode`, `MlDsaParameterSet`, `MlKemParameterSet` | Algorithm/mode choices |
| Default export | Legacy raw Emscripten factory |

The modern API uses `Uint8Array` for binary data, ships TypeScript declarations and wraps native errors in `AbeError` subclasses. CoverCrypt supports `HYBRIDIZED`, `POST_QUANTUM` and `CLASSIC` KEM modes; its post-quantum component is ML-KEM-768. Standalone `MlKem` supports 512/768/1024. AES supports 128/192/256 bits, and ML-DSA supports 44/65/87.

## CLI

~~~sh
npx @wanthinnn/pq-cp-abe --help
npx @wanthinnn/pq-cp-abe --test
~~~

The CLI uses **host file paths**. JavaScript file APIs use the **WASM virtual filesystem** instead; see the [CLI and build guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/docs/bindings/wasm/cli.md).

For native build and architecture details, see [WASM toolchain](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/bindings/wasm/README.md) and the [release workflow](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/.github/workflows/publish-npm.yml).
