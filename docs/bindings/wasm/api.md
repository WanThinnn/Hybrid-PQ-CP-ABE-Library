# JavaScript / TypeScript WebAssembly SDK — API reference

This page describes the implemented public API in [`bindings/wasm/loader.d.mts`](../../../bindings/wasm/loader.d.mts), [`api/functional.mjs`](../../../bindings/wasm/api/functional.mjs), [`abe/`](../../../bindings/wasm/abe/) and [`primitives/`](../../../bindings/wasm/primitives/). Use the declaration file for fully typed field definitions.

## Exports and factories

~~~js
import {
  PqCpAbe, AC17CPABE, TKN20CPABE, CoverCryptABE,
  Scheme, KemMode, MlDsaParameterSet, MlKemParameterSet,
  AesGcm, MlDsa, MlKem,
} from '@wanthinnn/pq-cp-abe';
~~~

| Entry point | Returns | Behavior |
| --- | --- | --- |
| `await PqCpAbe.create(options)` | object facade | Loads WASM; CoverCrypt is default |
| `await AC17CPABE.create()` / `TKN20CPABE.create()` | scheme object | Classical ABE |
| `await CoverCryptABE.create({config, mode})` | scheme object | Configured CoverCrypt |
| `instance.api` | functional API | Uses the instance's WASM runtime |

The factories are asynchronous. All cryptographic object/functional methods are synchronous once initialized. You can reuse one initialized native module across multiple object constructors.

### Enums

| Name | Members |
| --- | --- |
| `Scheme` | `AC17=0`, `TKN20=1`, `COVERCRYPT=2` |
| `KemMode` | `CLASSIC=0`, `POST_QUANTUM=1`, `HYBRIDIZED=2` |
| `MlDsaParameterSet` | `ML_DSA_44=44`, `ML_DSA_65=65`, `ML_DSA_87=87` |
| `MlKemParameterSet` | `ML_KEM_512=512`, `ML_KEM_768=768`, `ML_KEM_1024=1024` |

## Object interface: `PqCpAbe` and scheme classes

~~~js
const authority = await PqCpAbe.create({
  config: { dimensions: [{ name: 'role', attributes: ['admin'] }] },
  mode: KemMode.HYBRIDIZED,
});
console.log(authority.scheme);
~~~

For AC17 and TKN20 use `scheme: Scheme.AC17` or `Scheme.TKN20`, or construct `AC17CPABE` / `TKN20CPABE`. `config`/`mode`/`parameterSet` only apply to CoverCrypt.

| Method | Inputs | Return |
| --- | --- | --- |
| `setup()` | none | `{publicKey, masterSecretKey}` |
| `keygen({masterSecretKey, attributes})` | key `Uint8Array`, attribute `string` | user key `Uint8Array` |
| `generateSecretKey(options)` | alias of keygen | user key |
| `encrypt({publicKey, plaintext, policy, aesKeyBits?})` | key/data bytes + policy | ciphertext bytes |
| `decrypt({secretKey, ciphertext})` | bytes | plaintext bytes |
| `setupWithSigning({mlDsaParameterSet?})` | optional 44/65/87 | four authority/signing-key byte arrays |
| `encryptAndSign({publicKey, signingKey, plaintext, policy, aesKeyBits?, mlDsaParameterSet?})` | signing key in combined format | signed ciphertext |
| `decryptAndVerify({secretKey, verificationKey, ciphertext})` | user key and verification key | verified plaintext |

`PqCpAbe.backend` exposes the selected implementation; `scheme` is read-only. Decryption detects the ABE scheme from ciphertext; the keys must match the authority and scheme.

### CoverCrypt authority growth

`CoverCryptABE` exposes `addDimension({masterSecretKey, dimensionJson})` and `addAttribute({masterSecretKey, dimension, attribute, after?})`. Both return updated `{publicKey, masterSecretKey}`, which you must save. `addDimension` applies the instance mode; `addAttribute` currently uses the native environment mode `HCPABE_COVERCRYPT_MODE`. Extending an authority is **not** key revocation.

CoverCrypt uses ML-KEM-768 in its post-quantum component. It rejects other `parameterSet` values; the separate `MlKem` primitive supports more variants.

## Functional facade

Access the functional API through `instance.api`. Pass `scheme` to functional
methods that select a scheme.

| Method | Required fields (optional fields) | Return |
| --- | --- | --- |
| `setup` | (`scheme`) | authority keys |
| `covercryptSetup` | `configJson`, (`mode`) | authority keys |
| `setupWithSigning` | (`scheme`), (`mlDsaParameterSet`) | authority and signing keys |
| `generateSecretKey` | `masterSecretKey`, `attributes`, (`scheme`) | user key |
| `encrypt` | `publicKey`, `plaintext`, `policy`, (`scheme`), (`aesKeyBits`) | ciphertext |
| `decrypt` | `secretKey`, `ciphertext` | plaintext |
| `encryptAndSign` | `publicKey`, `signingKey`, `plaintext`, `policy`, optional scheme/parameters | signed ciphertext |
| `decryptAndVerify` | `secretKey`, `verificationKey`, `ciphertext` | verified plaintext |
| `covercryptAddDimension` | `masterSecretKey`, `dimensionJson`, (`mode`) | updated authority keys |
| `covercryptAddAttribute` | `masterSecretKey`, `dimension`, `attribute`, (`after`) | updated authority keys |
| `covercryptMlKemParameterSet` | none | 768 |
| `getVersion` | none | version string |

~~~js
import { PqCpAbe, Scheme } from '@wanthinnn/pq-cp-abe';

const { api } = await PqCpAbe.create();
const generated = api.setup({ scheme: Scheme.AC17 });
console.log(api.getVersion(), generated.publicKey.length);
~~~

### Virtual filesystem methods

File methods operate inside the **Emscripten FS**, not the real host filesystem:

- `setupFiles({outputPath, scheme?})`
- `setupFilesWithSigning({outputPath, scheme?, mlDsaParameterSet?, legacyKeyNames?})`
- `generateSecretKeyFile({masterSecretKeyPath, attributes, outputPath, scheme?})`
- `encryptFile({publicKeyPath, plaintextPath, policy, outputPath, scheme?, aesKeyBits?})`
- `decryptFile({secretKeyPath, ciphertextPath, outputPath})`
- `encryptAndSignFile({publicKeyPath, signingKeyPath, plaintextPath, policy, outputPath, scheme?, aesKeyBits?, mlDsaParameterSet?})`
- `decryptAndVerifyFile({secretKeyPath, verificationKeyPath, ciphertextPath, outputPath})`
- `covercryptAddDimensionFile(...)`, `covercryptAddAttributeFile(...)`

Transfer data with `api.native.FS.writeFile(...)` and `api.native.FS.readFile(...)`. Use `legacyKeyNames: false` for `ml-dsa_pk.key` / `ml-dsa_sk.key` names rather than legacy `pqc` labels. The npm CLI uses **host paths**; see [CLI guide](cli.md).

## Standalone primitives

Instantiate with an initialized native instance or the corresponding async class factory.

| Class | Constructor | Methods |
| --- | --- | --- |
| `AesGcm` | `new AesGcm(native, {keySizeBits: 256})` | `generateKey`, `generateNonce`, `encrypt({key, nonce, plaintext, aad?})`, `decrypt(...)` |
| `MlDsa` | `new MlDsa(native, {parameterSet: MlDsaParameterSet.ML_DSA_87})` | `generateKeypair`, `getSizes`, `sign({message, secretKey})`, `verify({message, signature, publicKey})` |
| `MlKem` | `new MlKem(native, {parameterSet: MlKemParameterSet.ML_KEM_768})` | `generateKeypair`, `getSizes`, `encapsulate({publicKey})`, `decapsulate({secretKey, ciphertext})` |

The functional `api` offers `aesGcmGenerateKey/Encrypt/Decrypt`, `mlDsaGenerateKeypair/GetSizes/Sign/Verify`, and `mlKemGenerateKeypair/GetSizes/Encapsulate/Decapsulate` with corresponding typed option objects.

`MlDsa.verify` returns `false` when the signature is invalid. `MlKem.encapsulate` returns `{ciphertext, sharedSecret}`; decapsulation returns `sharedSecret` only and is **not** an authenticity check. Generate a fresh AES-GCM nonce for each encryption under the same key.

## Errors, memory and formats

- Native operation failures raise `AbeError` (`code`, `operation`), with specialized `PolicyMismatchError` and `SignatureInvalidError`. Invalid arguments can raise `TypeError`/`RangeError`.
- Modern APIs return copied buffers and release native allocations. For raw `ccall` users, manual allocation, `freeBuffer` and FFI ownership rules remain your responsibility.
- Combined authority signing/verification values are **Base64-encoded Uint8Array**. Standalone `MlDsa` returns raw key bytes.
- AES sizes: 128/192/256; ML-DSA sets: 44/65/87. Explicit parameters select V3; omitted options preserve the legacy hybrid encryption path.
- Plain `decrypt` is not signature verification. Use `decryptAndVerify` and a **trusted** verification key for authenticated plaintext.

See the [native parameter and V3 format guide](../../native/parameters.md) and [project architecture](../../architecture/README.md).

## Compatibility imports

`createPqCpAbe` and `createHybridCpAbe` are aliases for the standalone
functional factory. The default export, `createHybridCPABE`, provides the raw
Emscripten module for integrations using `ccall`, `FS`, or `ENV`.
