---
title: JavaScript / WebAssembly SDK
description: Use PQ-CP-ABE from Node.js and browsers with the JavaScript/WebAssembly SDK, TypeScript declarations and policy-based hybrid encryption.
icon: lucide/cpu
---

# JavaScript / WebAssembly SDK

The `@wanthinnn/pq-cp-abe` npm package executes the project's cryptographic code through **WebAssembly**, not a native Node.js `.node` addon. It supports Node.js and modern browsers. C++/Rust/Crypto++/liboqs run in an Emscripten module, while CIRCL/TKN20 uses a separate Go `js/wasm` runtime.

## Documentation

- [Build from source](build.md) — Emscripten, Rust and Go toolchains, commands and deployment artifacts.
- [API reference](api.md) — objects, functional methods, enums, primitives, return values, errors.
- [CLI and build guide](cli.md) — host files, signed workflows, source builds and publishing.
- [Architecture and schemes](../../architecture/README.md) · [Native parameters and wire format](../../native/parameters.md).
- [WASM toolchain instructions](../../../bindings/wasm/README.md).

## Installation

~~~sh
npm install @wanthinnn/pq-cp-abe
~~~

Node.js 18+ is declared in the package manifest. For browsers, use HTTP(S) hosting and ensure the JS module and both WASM assets can be loaded by the bundler/server.

## Initialize the object API

~~~js
import { PqCpAbe, KemMode } from '@wanthinnn/pq-cp-abe';

const abe = await PqCpAbe.create({
  config: {
    dimensions: [
      { name: 'department', attributes: ['finance', 'engineering'] },
    ],
  },
  mode: KemMode.HYBRIDIZED,
});
console.log(abe.api.getVersion());
~~~

`PqCpAbe.create` asynchronously initializes the WASM runtimes. After initialization, cryptographic methods are synchronous; expensive operations can block the browser main thread. Use a Web Worker when appropriate.

### Working with CP-ABE keys and policies

Use `setup()` to create the authority, `keygen({masterSecretKey, attributes})` to issue a user key, `encrypt({publicKey, plaintext, policy})` to protect a `Uint8Array` and `decrypt({secretKey, ciphertext})` to recover it.

For a runnable complete example, see the [npm quick-start README](../../../bindings/npm/README.md). Keys and ciphertexts are scheme-specific; decryption detects the ciphertext scheme.

### Optional ML-DSA signing

Use `setupWithSigning({mlDsaParameterSet})` to generate additional ML-DSA signing/verification material, `encryptAndSign` to sign during encryption, and `decryptAndVerify` to validate before returning plaintext. **Signing-key setup does not sign the ABE public/master keys.**

### Functional API

Use `instance.api` for functional methods on the same WASM runtime.

~~~js
import { PqCpAbe, Scheme } from '@wanthinnn/pq-cp-abe';

const { api } = await PqCpAbe.create();
console.log(api.getVersion());
const authority = api.setup({ scheme: Scheme.AC17 });
console.log(authority.publicKey.length);
~~~

- All binary inputs/outputs in modern JavaScript methods use `Uint8Array`. The published package includes `loader.d.mts` for TypeScript.
- Errors from native calls become `AbeError` or a subclass, such as `PolicyMismatchError` and `SignatureInvalidError`. Incorrect JS inputs can raise `TypeError` or `RangeError`.

## Virtual filesystem versus host filesystem

The JavaScript methods `setupFiles`, `generateSecretKeyFile`, `encryptFile` and `decryptFile` operate on the **Emscripten in-memory filesystem**, not host OS paths:

~~~js
abe.native.FS.writeFile('/message.txt', new TextEncoder().encode('hello'));
const bytes = abe.native.FS.readFile('/message.txt');
console.log(bytes.length);
~~~

The npm command-line launcher uses Node.js to explicitly bridge files on the real host filesystem. See the [CLI guide](cli.md).

## Modes and defaults

| Parameter | Options | Default |
| --- | --- | --- |
| ABE | AC17 / TKN20 / CoverCrypt | CoverCrypt |
| CoverCrypt KEM | `CLASSIC` / `POST_QUANTUM` / `HYBRIDIZED` | HYBRIDIZED |
| ML-KEM in CoverCrypt | 768 | Fixed 768 |
| Standalone ML-KEM | 512 / 768 / 1024 | 768 |
| AES-GCM | 128 / 192 / 256 bits | 256 |
| Optional ML-DSA | 44 / 65 / 87 | 87 |

AC17/TKN20 are **classical ABE**; optional ML-DSA does not make their key encapsulation post-quantum. CoverCrypt's quantum-resistant encapsulation depends on its KEM mode.

## Security and compatibility notes

- Combined authority signing keys are Base64-encoded **byte arrays**; standalone `MlDsa` keys are raw bytes. Do not mix key formats.
- `CoverCryptABE.addDimension` and `addAttribute` produce a new public/master key pair. Save both; extending an authority does not automatically revoke existing user rights.
- Avoid AES-GCM nonce reuse. Standalone ML-KEM decapsulation is not sender authentication.
- WASM isolates linear memory but is not a secure key vault against malicious code executing in the same application.
- Explicit `aesKeyBits` / `mlDsaParameterSet` select the newer V3 hybrid ciphertext format; consult [parameters](../../native/parameters.md) for compatibility with older releases.
