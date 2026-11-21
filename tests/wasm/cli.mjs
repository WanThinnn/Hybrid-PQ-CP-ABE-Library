import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = process.argv[2] ?? fileURLToPath(new URL('../../bindings/wasm/cli.mjs', import.meta.url));
const config = fileURLToPath(new URL('../../scripts/covercrypt-demo.json', import.meta.url));
const cwd = mkdtempSync(join(tmpdir(), 'pq-cp-abe-wasm-cli-'));
const env = { ...process.env, HCPABE_COVERCRYPT_CONFIG: config, HCPABE_COVERCRYPT_MODE: 'hybridized' };
const invoke = (args, success = true) => {
  const result = spawnSync(process.execPath, [cli, ...args], { cwd, env, encoding: 'utf8', timeout: 60000 });
  assert.ifError(result.error);
  assert.equal(result.status === 0, success, result.stdout + result.stderr);
  return result;
};
const call = (...args) => invoke(args);

try {
  const attributes = 'Department::IT && Level::ADMIN';
  const data = Buffer.of(0, 128, 255);
  writeFileSync(join(cwd, 'plain'), data);
  assert.match(invoke(['--genkey'], false).stderr, /--master-key/);
  call('--setup', '--scheme', 'covercrypt', '--file', 'demo', '--with-signing-keys', '--ml-dsa', '65');
  call('--genkey', '--scheme', 'covercrypt', '--master-key', 'demo_msk.key',
    '--attributes', attributes, '--user-key', 'user.key');
  call('--encrypt', '--scheme', 'covercrypt', '--public-key', 'demo_pk.key',
    '--file', 'plain', '--policy', attributes, '--ciphertext', 'cipher', '--sign',
    '--signing-key', 'demo_ml-dsa_sk.key', '--aes-bits', '192', '--ml-dsa', '65');
  assert.deepEqual(readFileSync(join(cwd, 'cipher')).subarray(0, 4), Buffer.of(3, 2, 24, 65));
  call('--decrypt', '--verify', '--user-key', 'user.key', '--ciphertext', 'cipher',
    '--verification-key', 'demo_ml-dsa_pk.key', '--output', 'recovered');
  assert.deepEqual(readFileSync(join(cwd, 'recovered')), data);
  call('setup-pqc', '--scheme', 'ac17', 'legacy');
  assert.ok(readFileSync(join(cwd, 'legacy_pqc_sk.key')).length);
  call('add_attribute', '--scheme', 'covercrypt', 'demo_msk.key', 'Department', 'Ops', 'updated');
  assert.ok(readFileSync(join(cwd, 'updated_pk.key')).length);
  writeFileSync(join(cwd, 'dimension.json'), '{"name":"Zone","attributes":["EU","US"]}');
  call('add_dimension', '--scheme', 'covercrypt', 'updated_msk.key', 'dimension.json', 'grown');
  assert.ok(readFileSync(join(cwd, 'grown_msk.key')).length);
  const generated = call('setup_buffer', '--scheme', 'ac17', '--with-signing-keys', '--ml-dsa', '44');
  const keyLines = generated.stdout.trim().split(/\r?\n/);
  for (const [index, name] of ['pk', 'msk', 'verify', 'sign'].entries()) {
    writeFileSync(join(cwd, name), keyLines[index * 2 + 1]);
  }
  const user = call('genkey_buffer', '--scheme', 'ac17', 'msk', 'admin').stdout.trim().split(/\r?\n/).at(-1);
  writeFileSync(join(cwd, 'buffer-user'), user);
  call('encrypt_buffer', '--scheme', 'ac17', '--sign', '--ml-dsa', '44',
    'pk', 'sign', 'buffer message', 'admin', 'buffer-cipher');
  assert.match(call('decrypt_buffer', '--verify', 'buffer-user', 'verify', 'buffer-cipher').stdout,
    /Decrypted Buffer: buffer message/);
  console.log('PASS npm CLI 6.1: named flags, legacy setup, both growth operations and signed buffers');
} finally {
  rmSync(cwd, { recursive: true, force: true });
}
