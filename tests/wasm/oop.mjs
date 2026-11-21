import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';

const sdk = await import(process.argv[2] ? pathToFileURL(process.argv[2]).href : '../../lib/wasm/loader.mjs');
const { PqCpAbe, BaseCPABE, AC17CPABE, TKN20CPABE, CoverCryptABE, Scheme,
  KemMode, AesGcm, MlDsa, MlKem, AbeError } = sdk;
assert.equal(sdk.createPqCpAbe, sdk.createHybridCpAbe);
const config = { dimensions: [
  { name: 'role', attributes: ['admin', 'analyst'] },
  { name: 'department', attributes: ['finance', 'engineering'] },
] };
const first = await PqCpAbe.create({ scheme: Scheme.AC17 });
const native = first.native;
assert.equal(first.api.covercryptMlKemParameterSet(), 768);
assert.throws(() => new BaseCPABE(native), TypeError);
assert.ok(first.backend instanceof AC17CPABE);
for (const backend of [first, new TKN20CPABE(native),
  ...Object.values(KemMode).map(mode => new CoverCryptABE(native, { config, mode }))]) {
  assert.ok(backend instanceof BaseCPABE);
  assert.throws(() => { backend.scheme = 42; }, TypeError);
  const covercrypt = backend.scheme === Scheme.COVERCRYPT;
  const attributes = covercrypt ? 'role::admin department::finance' : 'admin it';
  const policy = covercrypt ? 'role::admin && department::finance' : 'admin and it';
  const keys = backend.setupWithSigning();
  const secretKey = backend.generateSecretKey({ masterSecretKey: keys.masterSecretKey, attributes });
  for (const plaintext of [new Uint8Array(), Uint8Array.of(0, 128, 255)]) {
    const ciphertext = backend.encrypt({ publicKey: keys.publicKey, plaintext, policy });
    assert.deepEqual(backend.decrypt({ secretKey, ciphertext }), plaintext);
    assert.deepEqual(backend.api.decrypt({ secretKey, ciphertext }), plaintext);
  }
  const plaintext = Uint8Array.of(1, 2, 3);
  const ciphertext = backend.encryptAndSign({ publicKey: keys.publicKey, signingKey: keys.signingKey, plaintext, policy });
  assert.deepEqual(backend.decryptAndVerify({ secretKey, verificationKey: keys.verificationKey, ciphertext }), plaintext);
  if (covercrypt) {
    const denied = backend.keygen({ masterSecretKey: keys.masterSecretKey, attributes: 'role::analyst department::engineering' });
    assert.throws(() => backend.decrypt({ secretKey: denied, ciphertext }), AbeError);
  }
}
for (const parameterSet of [44, 65, 87]) {
  const authority = first.setupWithSigning({ mlDsaParameterSet: parameterSet });
  const secretKey = first.keygen({ ...authority, attributes: 'admin' });
  const signer = new MlDsa(native, { parameterSet });
  assert.equal(signer.generateKeypair().publicKey.length, signer.getSizes().publicKey);
  for (const aesKeyBits of [128, 192, 256]) {
    const plaintext = Uint8Array.of(0, 255);
    const ciphertext = first.encryptAndSign({ ...authority, plaintext, policy: 'admin',
      aesKeyBits, mlDsaParameterSet: parameterSet });
    assert.deepEqual(ciphertext.slice(0, 4), Uint8Array.of(3, 0, aesKeyBits / 8, parameterSet));
    assert.deepEqual(first.decryptAndVerify({ ...authority, secretKey, ciphertext }), plaintext);
    const unsigned = first.encrypt({ ...authority, plaintext, policy: 'admin', aesKeyBits });
    assert.deepEqual(unsigned.slice(0, 4), Uint8Array.of(3, 0, aesKeyBits / 8, 0));
    assert.deepEqual(first.decrypt({ secretKey, ciphertext: unsigned }), plaintext);
  }
}
const authority = new CoverCryptABE(native, { config });
const grown = authority.addDimension({ ...authority.setup(),
  dimensionJson: '{"name":"zone","attributes":["eu"]}' });
const updated = authority.addAttribute({ ...grown, dimension: 'zone', attribute: 'us' });
const user = authority.keygen({ ...updated, attributes: 'zone::us' });
const messageByZone = Uint8Array.of(42);
const protectedByZone = authority.encrypt({ ...updated, plaintext: messageByZone, policy: 'zone::us' });
assert.deepEqual(authority.decrypt({ secretKey: user, ciphertext: protectedByZone }), messageByZone);
const snapshot = structuredClone(config);
const configured = new PqCpAbe(native, { config: snapshot });
snapshot.dimensions.length = 0;
assert.ok(configured.setup().publicKey.length);
assert.throws(() => new CoverCryptABE(native, { parameterSet: 512 }), RangeError);
assert.throws(() => new PqCpAbe(native, { scheme: Scheme.AC17, config }), TypeError);
for (const keySizeBits of [128, 192, 256]) {
  const aes = new AesGcm(native, { keySizeBits });
  const key = aes.generateKey(), nonce = aes.generateNonce();
  assert.equal(key.length * 8, keySizeBits);
  const aad = Uint8Array.of(42), plaintext = Uint8Array.of(1, 2, 3);
  const ciphertext = aes.encrypt({ key, nonce, plaintext, aad });
  assert.deepEqual(aes.decrypt({ key, nonce, ciphertext, aad }), plaintext);
  assert.throws(() => aes.decrypt({ key, nonce, ciphertext, aad: Uint8Array.of(0) }), AbeError);
  assert.throws(() => aes.encrypt({ key: new Uint8Array(1), nonce, plaintext }), RangeError);
  assert.throws(() => { aes.keySizeBits = 512; }, TypeError);
}
const signer = new MlDsa(native);
const keys = signer.generateKeypair(), message = Uint8Array.of(1, 2, 3);
const signature = signer.sign({ message, secretKey: keys.secretKey });
assert.equal(signer.verify({ message, signature, publicKey: keys.publicKey }), true);
assert.equal(signer.verify({ message: Uint8Array.of(0), signature, publicKey: keys.publicKey }), false);
assert.throws(() => signer.sign({ message, secretKey: new Uint8Array(2) }));

// New parameterized WASM exports may be absent from an older runtime. Report
// capability honestly; when present, exercise each parameter end to end.
if (typeof native._ml_kem_generate_keypair === 'function') {
  for (const parameterSet of [512, 768, 1024]) {
    const kem = new MlKem(native, { parameterSet });
    const keys = kem.generateKeypair();
    assert.equal(keys.publicKey.length, kem.getSizes().publicKey);
    const { ciphertext, sharedSecret } = kem.encapsulate({ publicKey: keys.publicKey });
    assert.deepEqual(kem.decapsulate({ secretKey: keys.secretKey, ciphertext }), sharedSecret);
  }
} else {
  assert.throws(() => new MlKem(native).generateKeypair(), /does not export ml_kem_generate_keypair/);
  console.log('WASM runtime predates standalone ML-KEM exports; unsupported operation rejected');
}
console.log('PASS WASM OOP: scheme backends, all CoverCrypt modes, signed bytes, AES sizes, ML-DSA and immutable configuration');
