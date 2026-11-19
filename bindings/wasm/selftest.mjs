import assert from 'node:assert/strict';

const requiredExports = `
  aes_gcm_decrypt aes_gcm_encrypt freeBuffer generateSecretKey generateSecretKey_with_scheme
  getErrorMessage getVersion hybrid_cpabe_covercrypt_add_attribute hybrid_cpabe_covercrypt_add_attributeBuffer
  hybrid_cpabe_covercrypt_add_dimension hybrid_cpabe_covercrypt_add_dimensionBuffer
  hybrid_cpabe_covercrypt_add_dimensionBuffer_with_mode hybrid_cpabe_covercrypt_setupBuffer_from_json
  hybrid_cpabe_decrypt
  hybrid_cpabe_decryptBuffer hybrid_cpabe_decryptBuffer_and_verify hybrid_cpabe_decrypt_and_verify
  hybrid_cpabe_encrypt hybrid_cpabe_encryptBuffer hybrid_cpabe_encryptBuffer_and_sign
  hybrid_cpabe_encryptBuffer_and_sign_with_scheme hybrid_cpabe_encryptBuffer_with_scheme
  hybrid_cpabe_encrypt_and_sign hybrid_cpabe_encrypt_and_sign_with_scheme hybrid_cpabe_encrypt_with_scheme
  hybrid_cpabe_genkeyBuffer_with_scheme hybrid_cpabe_setupBuffer_with_pqc_scheme
  hybrid_cpabe_setupBuffer_with_scheme hybrid_cpabe_setup_with_pqc hybrid_cpabe_setup_with_pqc_scheme
  ml_dsa_87_generate_keypair ml_dsa_87_sign ml_dsa_87_verify setup setup_with_scheme
`.trim().split(/\s+/);

function withHeap(abe, test) {
  const inputs = [];
  const slots = [];
  const allocate = size => {
    const address = abe._malloc(size);
    assert.ok(address, 'WASM allocation failed');
    return address;
  };
  const read = ([address]) => {
    const view = new DataView(abe.HEAPU8.buffer);
    return [view.getUint32(address, true), view.getUint32(address + 4, true)];
  };
  const heap = {
    input(data) {
      const address = allocate(data.length);
      inputs.push(address);
      abe.HEAPU8.set(data, address);
      return [address, data.length];
    },
    output() {
      const address = allocate(8);
      const slot = [address, address + 4];
      slots.push(slot);
      abe.HEAPU8.fill(0, address, address + 8);
      return slot;
    },
    read,
    bytes(slot) {
      const [address, size] = read(slot);
      return abe.HEAPU8.slice(address, address + size);
    },
  };
  try {
    test(heap);
  } finally {
    for (const slot of slots) {
      const [pointer] = read(slot);
      if (pointer) abe._freeBuffer(pointer);
      abe._free(slot[0]);
    }
    for (const pointer of inputs) abe._free(pointer);
  }
}

export async function runSelfTest(createHybridCPABE, expectedVersion) {
  const config = JSON.stringify({ dimensions: [
    { name: 'admin', attributes: ['present', 'absent'] },
    { name: 'it', attributes: ['present', 'absent'] },
  ] });
  const abe = await createHybridCPABE({
    preRun: [module => {
      module.ENV.HCPABE_COVERCRYPT_CONFIG = '/attribute-dimensions.json';
      module.ENV.HCPABE_COVERCRYPT_MODE = 'hybridized';
      module.FS.writeFile('/attribute-dimensions.json', config);
    }],
  });
  const called = new Set();
  const invoke = (name, type, ...parameters) => {
    const args = parameters.flat();
    const result = abe.ccall(name, type, args.map(arg => typeof arg === 'string' ? 'string' : 'number'), args);
    called.add(name);
    return result;
  };
  const call = (name, ...args) => invoke(name, 'number', ...args);
  const ok = (name, ...args) => assert.equal(call(name, ...args), 0, name);
  const fail = (name, ...args) => assert.notEqual(call(name, ...args), 0, name);
  const version = invoke('getVersion', 'string');
  if (expectedVersion) assert.equal(version, expectedVersion);
  else assert.match(version, /^\d+\.\d+\.\d+/);
  assert.ok(invoke('getErrorMessage', 'string', -5));
  invoke('freeBuffer', null, 0);
  console.log(`Running WASM self-test for v${version}`);

  const plain = Uint8Array.from([0, 1, 2, 127, 128, 255, 42]);
  abe.FS.writeFile('/plain', plain);

  withHeap(abe, ({ input, output, read, bytes }) => {
    const message = input(plain);
    const tampered = input(Uint8Array.of(7));
    const key = input(new Uint8Array(32));
    const aad = input(Uint8Array.of(1, 2));
    for (const length of [12, 24]) {
      const iv = input(new Uint8Array(length).fill(length));
      const encrypted = output();
      const decrypted = output();
      ok('aes_gcm_encrypt', key, iv, message, aad, encrypted);
      ok('aes_gcm_decrypt', key, iv, read(encrypted), aad, decrypted);
      assert.deepEqual(bytes(decrypted), plain);
      fail('aes_gcm_decrypt', key, iv, read(encrypted), tampered, output());
    }
    console.log('PASS AES-256-GCM: 12- and 24-byte nonces, wrong AAD rejected');

    const publicKey = output();
    const privateKey = output();
    const signature = output();
    ok('ml_dsa_87_generate_keypair', publicKey, privateKey);
    ok('ml_dsa_87_sign', message, read(privateKey)[0], signature);
    ok('ml_dsa_87_verify', message, read(signature), read(publicKey)[0]);
    fail('ml_dsa_87_verify', tampered, read(signature), read(publicKey)[0]);
    console.log('PASS ML-DSA-87: sign, verify, tampered message rejected');
  });

  const attrs = 'admin it';
  const policy = 'admin AND it';
  ok('setup', '/legacy');
  ok('generateSecretKey', '/legacy_msk.key', attrs, '/legacy_user.key');
  ok('hybrid_cpabe_encrypt', '/legacy_pk.key', '/plain', policy, '/legacy_ct');
  ok('hybrid_cpabe_decrypt', '/legacy_user.key', '/legacy_ct', '/legacy_recovered');
  assert.deepEqual(abe.FS.readFile('/legacy_recovered'), plain);
  ok('hybrid_cpabe_setup_with_pqc', '/legacy_pqc');
  ok('generateSecretKey', '/legacy_pqc_msk.key', attrs, '/legacy_pqc_user.key');
  ok('hybrid_cpabe_encrypt_and_sign', '/legacy_pqc_pk.key', '/legacy_pqc_pqc_sk.key',
     '/plain', policy, '/legacy_signed');
  ok('hybrid_cpabe_decrypt_and_verify', '/legacy_pqc_user.key', '/legacy_pqc_pqc_pk.key',
     '/legacy_signed', '/legacy_verified');
  assert.deepEqual(abe.FS.readFile('/legacy_verified'), plain);
  console.log('PASS legacy AC17 API');

  for (const [scheme, name] of ['AC17', 'TKN20', 'CoverCrypt'].entries()) {
    const prefix = `/scheme${scheme}`;
    ok('hybrid_cpabe_setup_with_pqc_scheme', prefix, scheme);
    ok('generateSecretKey_with_scheme', `${prefix}_msk.key`, attrs, `${prefix}_user.key`, scheme);
    ok('generateSecretKey_with_scheme', `${prefix}_msk.key`, 'admin', `${prefix}_denied.key`, scheme);
    ok('hybrid_cpabe_encrypt_with_scheme', `${prefix}_pk.key`, '/plain', policy, '/ct', scheme);
    ok('hybrid_cpabe_decrypt', `${prefix}_user.key`, '/ct', '/recovered');
    assert.deepEqual(abe.FS.readFile('/recovered'), plain);
    fail('hybrid_cpabe_decrypt', `${prefix}_denied.key`, '/ct', '/denied');
    ok('hybrid_cpabe_encrypt_and_sign_with_scheme', `${prefix}_pk.key`, `${prefix}_pqc_sk.key`,
       '/plain', policy, '/signed', scheme);
    ok('hybrid_cpabe_decrypt_and_verify', `${prefix}_user.key`, `${prefix}_pqc_pk.key`, '/signed', '/verified');
    assert.deepEqual(abe.FS.readFile('/verified'), plain);
    const tampered = abe.FS.readFile('/signed');
    tampered[tampered.length - 1] ^= 1;
    abe.FS.writeFile('/tampered', tampered);
    fail('hybrid_cpabe_decrypt_and_verify', `${prefix}_user.key`, `${prefix}_pqc_pk.key`, '/tampered', '/bad');

    withHeap(abe, ({ input, output, read, bytes }) => {
      const data = input(plain);
      const publicKey = output();
      const masterKey = output();
      const userKey = output();
      const ciphertext = output();
      const recovered = output();
      ok('hybrid_cpabe_setupBuffer_with_scheme', publicKey, masterKey, scheme);
      ok('hybrid_cpabe_genkeyBuffer_with_scheme', read(masterKey), attrs, userKey, scheme);
      ok('hybrid_cpabe_encryptBuffer_with_scheme', read(publicKey), data, policy, ciphertext, scheme);
      ok('hybrid_cpabe_decryptBuffer', read(userKey), read(ciphertext), recovered);
      assert.deepEqual(bytes(recovered), plain);

      const combinedPublicKey = output();
      const combinedMasterKey = output();
      const verifyKey = output();
      const signKey = output();
      ok('hybrid_cpabe_setupBuffer_with_pqc_scheme',
         combinedPublicKey, combinedMasterKey, verifyKey, signKey, scheme);
      for (const key of [combinedPublicKey, combinedMasterKey, verifyKey, signKey]) {
        assert.ok(read(key)[1], 'Expected a nonempty key');
      }
      const signed = output();
      const verified = output();
      ok('hybrid_cpabe_encryptBuffer_and_sign_with_scheme',
         read(publicKey), read(signKey), data, policy, signed, scheme);
      ok('hybrid_cpabe_decryptBuffer_and_verify', read(userKey), read(verifyKey), read(signed), verified);
      assert.deepEqual(bytes(verified), plain);
      if (scheme === 0) {
        const legacy = output();
        const legacySigned = output();
        const legacyRecovered = output();
        const legacyVerified = output();
        ok('hybrid_cpabe_encryptBuffer', read(publicKey), data, policy, legacy);
        ok('hybrid_cpabe_decryptBuffer', read(userKey), read(legacy), legacyRecovered);
        assert.deepEqual(bytes(legacyRecovered), plain);
        ok('hybrid_cpabe_encryptBuffer_and_sign', read(publicKey), read(signKey), data, policy, legacySigned);
        ok('hybrid_cpabe_decryptBuffer_and_verify',
           read(userKey), read(verifyKey), read(legacySigned), legacyVerified);
        assert.deepEqual(bytes(legacyVerified), plain);
      }
    });
    console.log(`PASS ${name}: file and buffer, denied policy, signature verification`);
  }

  const department = JSON.stringify({ name: 'department', attributes: ['engineering'] });
  const growthPolicy = 'admin::present && department::research';
  ok('setup_with_scheme', '/authority', 2);
  ok('hybrid_cpabe_covercrypt_add_dimension', '/authority_msk.key', department, '/authority_extended');
  ok('hybrid_cpabe_covercrypt_add_attribute', '/authority_extended_msk.key', 'department', 'research', 0, '/grown');
  ok('generateSecretKey_with_scheme', '/grown_msk.key', growthPolicy, '/grown_user.key', 2);
  ok('hybrid_cpabe_encrypt_with_scheme', '/grown_pk.key', '/plain', growthPolicy, '/grown_ct', 2);
  ok('hybrid_cpabe_decrypt', '/grown_user.key', '/grown_ct', '/grown_recovered');
  assert.deepEqual(abe.FS.readFile('/grown_recovered'), plain);

  withHeap(abe, ({ input, output, read, bytes }) => {
    const publicKey = output();
    const masterKey = output();
    ok('hybrid_cpabe_covercrypt_setupBuffer_from_json', config, 2, publicKey, masterKey);
    const extendedPublic = output();
    const extendedMaster = output();
    ok('hybrid_cpabe_covercrypt_add_dimensionBuffer', read(masterKey), department, extendedPublic, extendedMaster);
    const grownPublic = output();
    const grownMaster = output();
    ok('hybrid_cpabe_covercrypt_add_attributeBuffer',
       read(extendedMaster), 'department', 'research', 0, grownPublic, grownMaster);
    const userKey = output();
    const ciphertext = output();
    const recovered = output();
    ok('hybrid_cpabe_genkeyBuffer_with_scheme', read(grownMaster), growthPolicy, userKey, 2);
    ok('hybrid_cpabe_encryptBuffer_with_scheme', read(grownPublic), input(plain), growthPolicy, ciphertext, 2);
    ok('hybrid_cpabe_decryptBuffer', read(userKey), read(ciphertext), recovered);
    assert.deepEqual(bytes(recovered), plain);

    const explicitPublic = output();
    const explicitMaster = output();
    ok('hybrid_cpabe_covercrypt_add_dimensionBuffer_with_mode',
       read(masterKey), department, 2, explicitPublic, explicitMaster);
    assert.ok(read(explicitPublic)[1] && read(explicitMaster)[1], 'Expected both updated CoverCrypt keys');
  });
  console.log('PASS CoverCrypt authority growth: file and buffer APIs');

  const second = await createHybridCPABE();
  assert.equal(second.ccall('setup_with_scheme', 'number', ['string', 'number'], ['/second', 1]), 0);
  assert.equal(abe.FS.analyzePath('/second_pk.key').exists, false);
  assert.equal(second.callMain(['version']), 0);
  const missing = requiredExports.filter(name => !called.has(name));
  assert.deepEqual(missing, [], 'Public C exports that were not called');
  console.log(`PASS ${called.size}/${requiredExports.length} public C exports invoked`);
  console.log('WASM self-test passed');
}
