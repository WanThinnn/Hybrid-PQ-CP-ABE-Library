import assert from 'node:assert/strict';
import createHybridCPABE from '../../lib/wasm/loader.mjs';

const module = await createHybridCPABE({
  preRun: [m => {
    m.ENV.HCPABE_COVERCRYPT_CONFIG = '/covercrypt.json';
    m.ENV.HCPABE_COVERCRYPT_MODE = 'hybridized';
    m.FS.writeFile('/covercrypt.json', JSON.stringify({ dimensions: [
      { name: 'admin', attributes: ['present', 'absent'] },
      { name: 'it', attributes: ['present', 'absent'] },
    ] }));
  }],
});
const call = (name, args) => module.ccall(name, 'number',
  args.map(x => typeof x === 'string' ? 'string' : 'number'), args);
const ok = (name, args) => assert.equal(call(name, args), 0, name);
assert.match(module.ccall('getVersion', 'string', [], []), /^\d+\.\d+/);
const plain = Uint8Array.from([0, 1, 2, 127, 128, 255, 42]);
module.FS.writeFile('/plain', plain);

for (const [scheme, name] of ['AC17', 'TKN20', 'CoverCrypt'].entries()) {
  const prefix = `/scheme${scheme}`;
  ok('hybrid_cpabe_setup_with_pqc_scheme', [prefix, scheme]);
  ok('generateSecretKey_with_scheme', [`${prefix}_msk.key`, 'admin it', `${prefix}_user.key`, scheme]);
  ok('generateSecretKey_with_scheme', [`${prefix}_msk.key`, 'admin', `${prefix}_denied.key`, scheme]);
  ok('hybrid_cpabe_encrypt_with_scheme', [`${prefix}_pk.key`, '/plain', 'admin AND it', '/ct', scheme]);
  ok('hybrid_cpabe_decrypt', [`${prefix}_user.key`, '/ct', '/recovered']);
  assert.deepEqual(module.FS.readFile('/recovered'), plain);
  assert.notEqual(call('hybrid_cpabe_decrypt', [`${prefix}_denied.key`, '/ct', '/denied']), 0);
  ok('hybrid_cpabe_encrypt_and_sign_with_scheme', [
    `${prefix}_pk.key`, `${prefix}_pqc_sk.key`, '/plain', 'admin AND it', '/signed', scheme,
  ]);
  ok('hybrid_cpabe_decrypt_and_verify', [
    `${prefix}_user.key`, `${prefix}_pqc_pk.key`, '/signed', '/verified',
  ]);
  assert.deepEqual(module.FS.readFile('/verified'), plain);
  const tampered = module.FS.readFile('/signed');
  tampered[tampered.length - 1] ^= 1;
  module.FS.writeFile('/tampered', tampered);
  assert.notEqual(call('hybrid_cpabe_decrypt_and_verify', [
    `${prefix}_user.key`, `${prefix}_pqc_pk.key`, '/tampered', '/bad',
  ]), 0);
  // Exercise the wasm32 pointer/size_t ABI and ownership across both memories.
  const slots = module._malloc(40);
  const input = module._malloc(plain.length);
  module.HEAPU8.set(plain, input);
  module.HEAPU8.fill(0, slots, slots + 40);
  const word = offset => new DataView(module.HEAPU8.buffer).getUint32(slots + offset, true);
  try {
    ok('hybrid_cpabe_setupBuffer_with_scheme', [slots, slots + 4, slots + 8, slots + 12, scheme]);
    ok('hybrid_cpabe_genkeyBuffer_with_scheme', [word(8), word(12), 'admin it', slots + 16, slots + 20, scheme]);
    ok('hybrid_cpabe_encryptBuffer_with_scheme', [
      word(0), word(4), input, plain.length, 'admin AND it', slots + 24, slots + 28, scheme,
    ]);
    ok('hybrid_cpabe_decryptBuffer', [word(16), word(20), word(24), word(28), slots + 32, slots + 36]);
    assert.deepEqual(module.HEAPU8.slice(word(32), word(32) + word(36)), plain);
  } finally {
    for (const offset of [0, 8, 16, 24, 32]) module._freeBuffer(word(offset));
    module._free(input);
    module._free(slots);
  }
  console.log(`PASS ${name}: file/buffer round trip, denied policy, ML-DSA verification, tamper rejection`);
}
// Independent Emscripten instances share the persistent Go callback safely.
const second = await createHybridCPABE();
assert.equal(second.ccall('setup_with_scheme', 'number', ['string', 'number'], ['/second', 1]), 0);
assert.equal(module.FS.analyzePath('/second_pk.key').exists, false);
assert.equal(second.callMain(['version']), 0);
console.log('WASM smoke tests passed');
