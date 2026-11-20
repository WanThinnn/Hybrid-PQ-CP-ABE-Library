# PQ-CP-ABE JavaScript SDK

## Modern JavaScript / TypeScript API (additive)

Use the named `createHybridCpAbe` factory for camelCase methods and automatic
buffer management. The existing default `createHybridCPABE` export continues
to return the raw Emscripten module; its `ccall`, heap and filesystem APIs
are unchanged. TypeScript declarations are included.

```js
import { createHybridCpAbe } from '@wanthinnn/pq-cp-abe';

const config = JSON.stringify({ dimensions: [
  { name: 'role', attributes: ['admin', 'analyst'] },
  { name: 'department', attributes: ['finance', 'engineering'] },
] });
const abe = await createHybridCpAbe({ preRun: [module => {
  module.FS.writeFile('/attributes.json', config);
  module.ENV.HCPABE_COVERCRYPT_CONFIG = '/attributes.json';
  module.ENV.HCPABE_COVERCRYPT_MODE = 'hybridized';
}] });
const keys = abe.setup(); // Default: Scheme.COVERCRYPT
const secretKey = abe.generateSecretKey({
  masterSecretKey: keys.masterSecretKey,
  attributes: 'role::admin department::finance',
});
const ciphertext = abe.encrypt({
  publicKey: keys.publicKey,
  plaintext: new TextEncoder().encode('Hello'),
  policy: 'role::admin && department::finance',
});
console.log(new TextDecoder().decode(abe.decrypt({ secretKey, ciphertext })));
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
filesystem**, accessed through `abe.native.FS`, rather than host paths.
Setup retains native path/prefix naming. Native file operations may emit logs.

Native failures throw `AbeError` with `code` and `operation`; -3 and -9 map to
`PolicyMismatchError` and `SignatureInvalidError`. Generic cryptographic
failures (-4) remain `AbeError`. Input errors use `TypeError`/`RangeError`.
Existing low-level operations remain accessible through `abe.native`.

The factory returns an object bound to one WASM instance and holds no keys.
An application may wrap it in a class for configuration or resource ownership;
inheritance and stateful key storage are not required by the SDK.

Encrypt data under a policy such as `role::admin && department::finance`.
Only a user whose key satisfies that policy can decrypt it. This is
**ciphertext-policy attribute-based encryption (CP-ABE)**.

**CoverCrypt** provides post-quantum protection for ABE key encapsulation.
In its default `hybridized` mode, Curve25519 and ML-KEM-768 each contribute
a shared secret to the same encapsulation. AES-256-GCM encrypts the payload.
Optional ML-DSA-87 signatures can authenticate the signed data. AC17 and
TKN20 use classical ABE key protection.

## Quick start

Use Node.js 18 or newer. Install from npm after the package is published, or
run `npm install ./path/to/downloaded-package.tgz` with the npm tarball.

```sh
npm install @wanthinnn/pq-cp-abe
```

Save this as `version.mjs` and run `node version.mjs` to check the loaded
library version.

```js
import createHybridCPABE from '@wanthinnn/pq-cp-abe';

const abe = await createHybridCPABE();
console.log(abe.ccall('getVersion', 'string', [], []));
```

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
npx @wanthinnn/pq-cp-abe --config attributes-dimensions.json setup keys
npx @wanthinnn/pq-cp-abe genkey keys/cpabe_msk.key "role::admin department::finance" keys/finance.key
npx @wanthinnn/pq-cp-abe encrypt keys/cpabe_pk.key message.txt "role::admin && department::finance" message.enc
npx @wanthinnn/pq-cp-abe decrypt keys/finance.key message.enc recovered.txt
node -e "console.log(require('node:fs').readFileSync('recovered.txt', 'utf8'))"
```

The CLI accepts host paths for all input and output files and requires new
output filenames. CoverCrypt `genkey` updates the master key with its tracing
records. Use `--scheme ac17` or `--scheme tkn20` with setup, key generation,
and encryption to work with classical keys. Decryption detects the scheme.

Use `setup-pqc`, `encrypt-pqc`, and `decrypt-pqc` to add ML-DSA-87 signatures
and verification. Keep the signing key with the party authorized to sign.

```sh
mkdir signed-keys
npx @wanthinnn/pq-cp-abe --config attributes-dimensions.json setup-pqc signed-keys
npx @wanthinnn/pq-cp-abe genkey signed-keys/cpabe_msk.key "role::admin department::finance" signed-keys/finance.key
npx @wanthinnn/pq-cp-abe encrypt-pqc signed-keys/cpabe_pk.key signed-keys/pqc_sk.key message.txt "role::admin && department::finance" signed.enc
npx @wanthinnn/pq-cp-abe decrypt-pqc signed-keys/finance.key signed-keys/pqc_pk.key signed.enc verified.txt
```

### Run a post-quantum ABE example in Node.js

Save this as `demo.mjs` and run `node demo.mjs`. It creates a CoverCrypt
authority and issues a key for an admin in the finance department. It verifies
that this key decrypts the message and that an engineering admin is denied.
Each step reports `OK` or `FAILED`.

```js
import createHybridCPABE from '@wanthinnn/pq-cp-abe';

const scheme = 2; // CoverCrypt
const mode = 'hybridized';
const policy = 'role::admin && department::finance';
const message = 'Hello from PQ-CP-ABE';
const dimensions = [
  { name: 'role', attributes: ['admin', 'analyst'] },
  { name: 'department', attributes: ['finance', 'engineering'] },
];

let stepNumber = 0;
async function step(label, action) {
  const prefix = `[${++stepNumber}] ${label}`;
  try {
    const result = await action();
    console.log(`${prefix}: OK`);
    return result;
  } catch (error) {
    throw new Error(`${prefix}: FAILED (${error.message})`);
  }
}

try {
  const abe = await step('Initialize CoverCrypt', () => createHybridCPABE({
    preRun: [module => {
      const config = '/attributes-dimensions.json';
      module.FS.writeFile(config, JSON.stringify({ dimensions }));
      module.ENV.HCPABE_COVERCRYPT_CONFIG = config;
      module.ENV.HCPABE_COVERCRYPT_MODE = mode;
    }],
  }));

  function call(name, ...args) {
    const types = args.map(value => typeof value === 'number' ? 'number' : 'string');
    return abe.ccall(name, 'number', types, args);
  }
  function describeError(code) {
    return abe.ccall('getErrorMessage', 'string', ['number'], [code]);
  }
  function checked(name, ...args) {
    const code = call(name, ...args);
    if (code !== 0) throw new Error(`${name}: ${describeError(code)} (${code})`);
  }

  await step('Create authority keys', () => {
    checked('setup_with_scheme', '/authority', scheme);
  });
  await step('Issue the finance admin key', () => {
    checked('generateSecretKey_with_scheme', '/authority_msk.key',
      'role::admin department::finance', '/finance.key', scheme);
  });
  await step('Encrypt under the policy', () => {
    abe.FS.writeFile('/message.txt', message);
    checked('hybrid_cpabe_encrypt_with_scheme', '/authority_pk.key',
      '/message.txt', policy, '/message.enc', scheme);
  });
  await step('Decrypt and compare the recovered message', () => {
    checked('hybrid_cpabe_decrypt', '/finance.key', '/message.enc', '/recovered.txt');
    const recovered = abe.FS.readFile('/recovered.txt', { encoding: 'utf8' });
    if (recovered !== message) throw new Error('The recovered message differs');
    console.log(`    Recovered: ${recovered}`);
  });
  await step('Check that an engineering admin is denied', () => {
    checked('generateSecretKey_with_scheme', '/authority_msk.key',
      'role::admin department::engineering', '/engineering.key', scheme);
    const code = call('hybrid_cpabe_decrypt', '/engineering.key', '/message.enc', '/denied.txt');
    if (code !== -3) {
      throw new Error(`Expected a policy mismatch, got ${describeError(code)} (${code})`);
    }
  });
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
```

The authority keeps the master secret key and uses it to issue user keys.
Encryptors use the public key. File paths in this example refer to the
WASM filesystem. Use Node's `node:fs/promises` to load host files and pass
their bytes to `abe.FS.writeFile()`. Use `abe.FS.readFile()` to get bytes to
save back to disk.

### Choose hybrid or PQC-only key encapsulation

Set `HCPABE_COVERCRYPT_MODE` on the WASM module before creating authority keys.
In the demo, change the `mode` constant and rerun it to create a new authority.
For the CLI, use `--mode post_quantum` with `setup` or `setup-pqc`. The CLI also
accepts `HCPABE_COVERCRYPT_CONFIG` and `HCPABE_COVERCRYPT_MODE` from the shell.

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

### Public WASM API

The factory exposes `ccall`, `FS`, and `callMain`. Pass scheme `0` for AC17,
`1` for TKN20, or `2` for CoverCrypt to setup, key generation and encryption.
Decryption reads the scheme from the ciphertext. When using C buffer APIs,
release library-allocated output with `freeBuffer`. See the
[public C signatures](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h)
and [WASM guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/tree/main/bindings/wasm).

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
