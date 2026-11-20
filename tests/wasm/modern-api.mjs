import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { wrapModule, Scheme, AbeError } from '../../bindings/wasm/api.mjs';

// Exercise ownership even when native code returns partial output then fails.
for (const failure of [false, true]) {
  const freed = [];
  const released = [];
  let next = 8;
  const native = {
    HEAPU8: new Uint8Array(256),
    _malloc(size) { const pointer = next; next += size; return pointer; },
    _free(pointer) { freed.push(pointer); },
    _freeBuffer(pointer) { released.push(pointer); },
    ccall(name, type, types, args) {
      if (name === 'getErrorMessage') return 'mock error';
      // Simulate heap growth during the native operation.
      this.HEAPU8 = new Uint8Array(512);
      const view = new DataView(this.HEAPU8.buffer);
      view.setUint32(args[0], 200, true);
      view.setUint32(args[1], 3, true);
      this.HEAPU8.set([1, 2, 3], 200);
      view.setUint32(args[2], 210, true);
      view.setUint32(args[3], 1, true);
      this.HEAPU8[210] = 4;
      return failure ? -4 : 0;
    },
  };
  const api = wrapModule(native);
  if (failure) assert.throws(() => api.setup(), error => error instanceof AbeError && error.code === -4);
  else {
    const keys = api.setup();
    native.HEAPU8.fill(0);
    assert.deepEqual(keys.publicKey, Uint8Array.of(1, 2, 3));
  }
  assert.deepEqual(released, [200, 210]);
  assert.equal(freed.length, 2);
}

const loader = process.argv[2];
const { default: createRaw, createHybridCpAbe, AbeError: RuntimeAbeError } = await import(
  loader ? pathToFileURL(loader).href : '../../lib/wasm/loader.mjs');
const config = JSON.stringify({ dimensions: [
  { name: 'admin', attributes: ['present', 'absent'] },
  { name: 'it', attributes: ['present', 'absent'] },
] });
const options = { preRun: [module => {
  module.FS.writeFile('/config.json', config);
  module.ENV.HCPABE_COVERCRYPT_CONFIG = '/config.json';
  module.ENV.HCPABE_COVERCRYPT_MODE = 'hybridized';
}] };
assert.equal(typeof createRaw, 'function');
const abe = await createHybridCpAbe(options);
assert.equal(typeof abe.native.ccall, 'function');
for (const scheme of Object.values(Scheme)) {
  const keys = abe.setupWithSigning({ scheme });
  const secretKey = abe.generateSecretKey({ masterSecretKey: keys.masterSecretKey, attributes: 'admin it', scheme });
  for (const plaintext of [new Uint8Array(), Uint8Array.of(0, 1, 127, 255)]) {
    const ciphertext = abe.encrypt({ publicKey: keys.publicKey, plaintext, policy: 'admin and it', scheme });
    assert.deepEqual(abe.decrypt({ secretKey, ciphertext }), plaintext);
  }
  const plaintext = Uint8Array.of(1, 2, 3);
  const ciphertext = abe.encryptAndSign({ publicKey: keys.publicKey, signingKey: keys.signingKey,
    plaintext, policy: 'admin and it', scheme });
  assert.deepEqual(abe.decryptAndVerify({ secretKey, verificationKey: keys.verificationKey, ciphertext }), plaintext);
  ciphertext[ciphertext.length - 1] ^= 1;
  assert.throws(() => abe.decryptAndVerify({ secretKey, verificationKey: keys.verificationKey, ciphertext }), RuntimeAbeError);
  const prefix = `/scheme${scheme}`;
  abe.setupFilesWithSigning({ outputPath: prefix, scheme });
  abe.generateSecretKeyFile({ masterSecretKeyPath: `${prefix}_msk.key`, attributes: 'admin it', outputPath: '/user', scheme });
  abe.native.FS.writeFile('/plain', plaintext);
  abe.encryptFile({ publicKeyPath: `${prefix}_pk.key`, plaintextPath: '/plain', policy: 'admin and it', outputPath: '/cipher', scheme });
  abe.decryptFile({ secretKeyPath: '/user', ciphertextPath: '/cipher', outputPath: '/recovered' });
  assert.deepEqual(abe.native.FS.readFile('/recovered'), plaintext);
  abe.encryptAndSignFile({ publicKeyPath: `${prefix}_pk.key`, signingKeyPath: `${prefix}_pqc_sk.key`,
    plaintextPath: '/plain', policy: 'admin and it', outputPath: '/cipher', scheme });
  abe.decryptAndVerifyFile({ secretKeyPath: '/user', verificationKeyPath: `${prefix}_pqc_pk.key`,
    ciphertextPath: '/cipher', outputPath: '/recovered' });
  assert.deepEqual(abe.native.FS.readFile('/recovered'), plaintext);
  assert.ok(abe.setup({ scheme }).publicKey.length);
}
assert.throws(() => abe.setup({ scheme: 42 }), RangeError);
assert.throws(() => abe.encrypt({ publicKey: 'invalid', plaintext: new Uint8Array(), policy: 'admin' }), TypeError);
console.log('PASS modern WASM API: all schemes, signed buffers, files, validation and cleanup');
