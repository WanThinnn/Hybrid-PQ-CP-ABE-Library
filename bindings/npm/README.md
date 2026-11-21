# PQ-CP-ABE JavaScript SDK
A Native Post-Quantum Ciphertext-Policy Attribute-Based Encryption SDK for WebAssembly. It combines
AC17, TKN20, or CoverCrypt with AES-GCM and optional ML-DSA signatures. CoverCrypt
supports ML-KEM-768 for key encapsulation. AC17 and TKN20 use classical ABE.


## Quick start

Use Node.js 18 or newer. Install from npm after the package is published, or
run `npm install ./path/to/downloaded-package.tgz` with the npm tarball.

```sh
npm install @wanthinnn/pq-cp-abe
```

Save this as `version.mjs` and run `node version.mjs` to check the loaded
library version.

```js
import { PqCpAbe } from '@wanthinnn/pq-cp-abe';

const { api } = await PqCpAbe.create();
console.log(api.getVersion());
```



## Functional JavaScript and TypeScript API

Access the functional methods through `instance.api` after
`await PqCpAbe.create()`. This API provides automatic buffer management and
TypeScript declarations. The standalone exports `createPqCpAbe` and
`createHybridCpAbe` remain available for existing imports.

```js
import { PqCpAbe, KemMode } from '@wanthinnn/pq-cp-abe';

const configJson = JSON.stringify({ dimensions: [
  { name: 'role', attributes: ['admin', 'analyst'] },
  { name: 'department', attributes: ['finance', 'engineering'] },
] });
const { api } = await PqCpAbe.create();
const keys = api.covercryptSetup({ configJson, mode: KemMode.HYBRIDIZED });
const secretKey = api.generateSecretKey({
  masterSecretKey: keys.masterSecretKey,
  attributes: 'role::admin department::finance',
});
const ciphertext = api.encrypt({
  publicKey: keys.publicKey,
  plaintext: new TextEncoder().encode('Hello'),
  policy: 'role::admin && department::finance',
});
console.log(new TextDecoder().decode(api.decrypt({ secretKey, ciphertext })));
```

Only factory initialization is asynchronous; crypto methods are synchronous
and can block the calling thread. Use a worker if needed. Pass the same
`scheme: Scheme.AC17` or `Scheme.TKN20` to setup, key generation and encryption
to choose a different scheme; decryption detects the ciphertext scheme.
Scheme-specific attribute/policy syntax is unchanged.

| In-memory API | File API |
| --- | --- |
| `setup()` | `setupFiles({ outputPath })` |
| `setupWithSigning()` | `setupFilesWithSigning({ outputPath })` |
| `generateSecretKey(...)` | `generateSecretKeyFile(...)` |
| `encrypt(...)` / `decrypt(...)` | `encryptFile(...)` / `decryptFile(...)` |
| `encryptAndSign(...)` | `encryptAndSignFile(...)` |
| `decryptAndVerify(...)` | `decryptAndVerifyFile(...)` |

Binary inputs/outputs are `Uint8Array`. Output arrays are copied before native
buffers are freed, including cleanup after errors. `setup()` returns
`{ publicKey, masterSecretKey }`; `setupWithSigning()` additionally returns
`verificationKey` and `signingKey` as native Base64-encoded bytes for the
combined signing operations (not raw standalone ML-DSA keys).
File methods return `undefined`; their paths refer to the **WASM virtual
filesystem**, accessed through `api.native.FS`.
Setup retains native path/prefix naming. Native file operations may emit logs.

Native failures throw `AbeError` with `code` and `operation`; -3 and -9 map to
`PolicyMismatchError` and `SignatureInvalidError`. Generic cryptographic
failures (-4) remain `AbeError`. Input errors use `TypeError`/`RangeError`.
Low-level operations are available through `api.native`.

Both functional and object APIs bind to a WASM instance and hold no keys.
Applications can share that instance through the OOP constructors.

Encrypt data under a policy such as `role::admin && department::finance`.
Only a user whose key satisfies that policy can decrypt it. This is
**ciphertext-policy attribute-based encryption (CP-ABE)**.

**CoverCrypt** provides post-quantum protection for ABE key encapsulation.
In its default `hybridized` mode, Curve25519 and ML-KEM-768 each contribute
a shared secret to the same encapsulation. AES-GCM encrypts the payload.
Optional ML-DSA signatures can authenticate the signed data. AC17 and
TKN20 use classical ABE key protection.

## Object API

The named `PqCpAbe` class offers the same scheme interface as Python, with
camelCase methods. Async factories initialize WASM; cryptographic methods
then run synchronously. Pass an existing initialized native module to a
constructor to share one runtime between multiple objects.

```js
import { PqCpAbe, AesGcm, MlDsa, MlKem, MlDsaParameterSet, MlKemParameterSet }
  from '@wanthinnn/pq-cp-abe';

const abe = await PqCpAbe.create({ config: { dimensions: [
  { name: 'role', attributes: ['admin', 'analyst'] },
  { name: 'department', attributes: ['finance', 'engineering'] },
] } });
const keys = abe.setup();
const secretKey = abe.keygen({ masterSecretKey: keys.masterSecretKey,
  attributes: 'role::admin department::finance' });
const ciphertext = abe.encrypt({ publicKey: keys.publicKey,
  plaintext: new TextEncoder().encode('Hello'), policy: 'role::admin && department::finance' });
console.log(new TextDecoder().decode(abe.decrypt({ secretKey, ciphertext })));

const aes = new AesGcm(abe.native, { keySizeBits: 192 });
const signer = new MlDsa(abe.native, { parameterSet: MlDsaParameterSet.ML_DSA_65 });
const kem = new MlKem(abe.native, { parameterSet: MlKemParameterSet.ML_KEM_1024 });
```

`AC17CPABE`, `TKN20CPABE` and `CoverCryptABE` implement `BaseCPABE`.
Each supports `setup`, `keygen` (alias `generateSecretKey`), `encrypt`,
`decrypt`, `setupWithSigning`, `encryptAndSign` and `decryptAndVerify`.
For example `await AC17CPABE.create()` initializes an AC17 object;
`new AC17CPABE(abe.native)` reuses a runtime. OOP methods use in-memory bytes;
file methods remain available through the functional API.

`AesGcm` offers `generateKey`, `generateNonce`, `encrypt` and `decrypt`.
Pass `{ key, nonce, plaintext, aad }` to encrypt; keep the nonce and AAD for
decryption and use a fresh nonce with each encryption under a given key.
`MlDsa` offers `generateKeypair`, `sign({ message, secretKey })` and
`verify({ message, signature, publicKey })`. `MlKem` offers `generateKeypair`,
`encapsulate({ publicKey })` and `decapsulate({ secretKey, ciphertext })`;
encapsulation returns `{ ciphertext, sharedSecret }` and decapsulation returns
the secret bytes. ML-KEM decapsulation alone does not authenticate ciphertexts.

`encrypt` and `encryptAndSign` accept `aesKeyBits` (128, 192, or 256).
For signed encryption, pass the same `mlDsaParameterSet` (44, 65, or 87) to
`setupWithSigning` and `encryptAndSign`. Omitting both parameters uses
AES-256 and ML-DSA-87 with the legacy ciphertext format.

CoverCrypt snapshots its configuration and uses the selected `KemMode`.
Its post-quantum component uses ML-KEM-768. The standalone `MlKem` class
supports ML-KEM-512, ML-KEM-768, and ML-KEM-1024. Use `getSizes()` on
`MlDsa` or `MlKem` to query sizes for the selected parameter set.

Source layout separates `api/legacy.mjs` (raw module entry),
`api/functional.mjs` (modern operations), `abe/`, `primitives/`, `models/`,
`utils/` and internal `runtime/`. `loader.mjs` remains the public entry;
its default export retains the raw Emscripten factory.

### CLI and self-test

```sh
npx @wanthinnn/pq-cp-abe --help
npx @wanthinnn/pq-cp-abe version
npx @wanthinnn/pq-cp-abe --test
```

The CLI exercises the public C API through the bundled WASM, including AC17,
TKN20, CoverCrypt authority growth, AES-256-GCM, and ML-DSA-87. It checks that
unauthorized keys and tampered data are rejected, reports the number of C
exports invoked, and returns a nonzero exit status if a check fails.

### Post-quantum ABE from the CLI

The CLI uses CoverCrypt by default. In a new working directory, save this as
`attributes-dimensions.json`:

```json
{
  "dimensions": [
    { "name": "role", "attributes": ["admin", "analyst"] },
    { "name": "department", "attributes": ["finance", "engineering"] }
  ]
}
```

```sh
mkdir keys
node -e "require('node:fs').writeFileSync('message.txt', 'Hello from PQ-CP-ABE')"
npx @wanthinnn/pq-cp-abe --setup --scheme covercrypt --config attributes-dimensions.json --file keys
npx @wanthinnn/pq-cp-abe --genkey --scheme covercrypt --master-key keys/cpabe_msk.key --attributes "role::admin department::finance" --user-key keys/finance.key
npx @wanthinnn/pq-cp-abe --encrypt --scheme covercrypt --public-key keys/cpabe_pk.key --file message.txt --policy "role::admin && department::finance" --ciphertext message.enc
npx @wanthinnn/pq-cp-abe --decrypt --user-key keys/finance.key --ciphertext message.enc --output recovered.txt
node -e "console.log(require('node:fs').readFileSync('recovered.txt', 'utf8'))"
```

The CLI accepts host paths for all input and output files and requires new
output filenames. CoverCrypt `genkey` updates the master key with its tracing
records. Use `--scheme ac17` or `--scheme tkn20` with setup, key generation,
and encryption to work with classical keys. Decryption detects the scheme.

The signed flow below uses AES-192 and ML-DSA-65. Omitting the parameter flags
uses AES-256 and ML-DSA-87. Existing scripts can continue using the positional
syntax or the `setup-pqc`, `encrypt-pqc`, and `decrypt-pqc` commands.

```sh
npx @wanthinnn/pq-cp-abe --setup --scheme covercrypt --config attributes-dimensions.json --file signed --with-signing-keys --ml-dsa 65
npx @wanthinnn/pq-cp-abe --genkey --scheme covercrypt --master-key signed_msk.key --attributes "role::admin department::finance" --user-key user.key
npx @wanthinnn/pq-cp-abe --encrypt --scheme covercrypt --sign --public-key signed_pk.key --signing-key signed_ml-dsa_sk.key --file message.txt --policy "role::admin && department::finance" --ciphertext signed.enc --aes-bits 192 --ml-dsa 65
npx @wanthinnn/pq-cp-abe --decrypt --verify --user-key user.key --verification-key signed_ml-dsa_pk.key --ciphertext signed.enc --output verified.txt
```

For the functional API and CP-ABE classes, use `aesKeyBits` during encryption
and `mlDsaParameterSet` during signed setup and encryption. Decryption detects
the ciphertext format and parameters. Pass `legacyKeyNames: false` to
`setupFilesWithSigning` to get the new ML-DSA filenames in the WASM filesystem.
`CoverCryptABE.addDimension` uses the instance mode. `addAttribute` uses
`native.ENV.HCPABE_COVERCRYPT_MODE`. Save both keys from either operation.

### Sign and encrypt with CoverCryptABE

Save this as `demo.mjs` and run `node demo.mjs`. It verifies the signature and
checks that a key with the wrong department is denied.

```js
import { CoverCryptABE, KemMode, MlDsaParameterSet, PolicyMismatchError }
  from '@wanthinnn/pq-cp-abe';

const authority = await CoverCryptABE.create({
  config: { dimensions: [
    { name: 'role', attributes: ['admin', 'analyst'] },
    { name: 'department', attributes: ['finance', 'engineering'] },
  ] },
  mode: KemMode.HYBRIDIZED,
});
const mlDsaParameterSet = MlDsaParameterSet.ML_DSA_65;
const { publicKey, masterSecretKey, signingKey, verificationKey } =
  authority.setupWithSigning({ mlDsaParameterSet });
const secretKey = authority.keygen({
  masterSecretKey, attributes: 'role::admin department::finance',
});
const message = 'Hello from PQ-CP-ABE';
const ciphertext = authority.encryptAndSign({
  publicKey, signingKey, plaintext: new TextEncoder().encode(message),
  policy: 'role::admin && department::finance', aesKeyBits: 192, mlDsaParameterSet,
});
const recovered = authority.decryptAndVerify({ secretKey, verificationKey, ciphertext });
if (new TextDecoder().decode(recovered) !== message) throw new Error('Unexpected plaintext');

const otherKey = authority.keygen({
  masterSecretKey, attributes: 'role::admin department::engineering',
});
try {
  authority.decryptAndVerify({ secretKey: otherKey, verificationKey, ciphertext });
  throw new Error('An engineering key decrypted the finance message');
} catch (error) {
  if (!(error instanceof PolicyMismatchError)) throw error;
  console.log('Engineering access denied');
}
```

### Choose hybrid or PQC-only key encapsulation

In the class example, pass `mode: KemMode.POST_QUANTUM` to
`CoverCryptABE.create` before generating new keys. For the CLI, pass
`--mode post_quantum` to `--setup`, or set `HCPABE_COVERCRYPT_MODE` in your shell.

| Mode | CoverCrypt key encapsulation |
| --- | --- |
| `hybridized` (default) | Curve25519 and ML-KEM-768 both contribute to encapsulation. |
| `post_quantum` | ML-KEM-768 alone. |
| `classic` | The classical Curve25519-based component alone. |

The public key records the modes of its protected attributes. Changing the
setting for setup leaves previously issued keys and ciphertext unchanged.
See the [C++ mode selector](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/src/schemes/covercrypt.cpp)
and [CoverCrypt encapsulation implementation](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/vendor/cover_crypt/src/abe/core/primitives.rs)
for implementation details.

### Native WASM reference

The functional API exposes the initialized module through `api.native` for
direct C ABI access. Its file methods use the Emscripten filesystem. [Public C signatures](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h) · [WASM guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/wasm)

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
temporary Node.js project and runs the installed CLI self-test. The tested
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
