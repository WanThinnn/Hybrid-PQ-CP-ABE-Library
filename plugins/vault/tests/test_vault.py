"""Real HTTP tests. --docker runs only the Vault service, never the build."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[3]
CONFIG = json.dumps({'dimensions': [
    {'name': 'Department', 'attributes': ['IT', 'HR']},
    {'name': 'Level', 'attributes': ['USER', 'ADMIN']},
]})


def api(path, data=None, *, address=None, token=None, method=None):
    address = address or os.environ.get('VAULT_ADDR', 'http://127.0.0.1:8201')
    token = token or os.environ.get('VAULT_TOKEN')
    if not token:
        raise RuntimeError('Set VAULT_TOKEN for a dedicated development Vault')
    request = urllib.request.Request(address.rstrip('/') + '/v1/' + path,
                                     data=None if data is None else json.dumps(data).encode(),
                                     method=method or ('GET' if data is None else 'PUT'),
                                     headers={'X-Vault-Token': token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=180) as response:
        body = response.read()
        return json.loads(body) if body else {}


class VaultHTTPTests(unittest.TestCase):
    def call(self, path, data, denied=False, error_code='-3'):
        mount = os.environ.get('VAULT_ABE_MOUNT', 'abe').strip('/')
        try:
            result = api(f'{mount}/{path}', data)['data']
        except urllib.error.HTTPError as error:
            detail = error.read().decode()
            if not denied:
                self.fail(f'{path}: HTTP {error.code}: {detail}')
            self.assertEqual(error.code, 400, detail)
            if error_code is not None:
                self.assertIn(error_code, detail, detail)
            return None
        self.assertFalse(denied, 'Unauthorized user decrypted the ciphertext')
        return result

    def test_all_schemes(self):
        cases = [
            ('ac17', 'admin it', 'guest', 'admin and it'),
            ('tkn20', 'role:admin,dept:it', 'role:guest', 'role:admin and dept:it'),
            ('covercrypt', 'Department::IT Level::ADMIN', 'Department::IT', 'Department::IT && Level::ADMIN'),
        ]
        for scheme, attrs, denied, policy in cases:
            for signed in (False, True):
                with self.subTest(scheme=scheme, signed=signed):
                    print(f'HTTP: {scheme}, signatures={signed}', flush=True)
                    params = {'scheme': scheme, 'pqc': signed}
                    if scheme == 'covercrypt':
                        params['config_json'] = CONFIG
                    setup = self.call('setup', params)
                    self.assertEqual(setup['native_version'], (ROOT / 'VERSION').read_text().strip())
                    user = self.call('genkey', {'scheme': scheme, 'attributes': attrs})
                    wrong = self.call('genkey', {'scheme': scheme, 'attributes': denied})
                    plain = base64.b64encode(b'Vault HTTP real crypto\x00\xff').decode()
                    encrypted = self.call('encrypt', {'scheme': scheme, 'public_key': setup['public_key'],
                                                      'plaintext': plain, 'policy': policy})
                    data = {'secret_key': user['secret_key'], 'ciphertext': encrypted['ciphertext']}
                    if signed:
                        data['pqc_public_key'] = setup['pqc_public_key']
                    self.assertEqual(self.call('decrypt', data)['plaintext'], plain)
                    data['secret_key'] = wrong['secret_key']
                    self.call('decrypt', data, denied=True)

    def test_covercrypt_or(self):
        setup = self.call('setup', {'scheme': 'covercrypt', 'config_json': CONFIG})
        encrypted = self.call('encrypt', {'scheme': 'covercrypt', 'public_key': setup['public_key'],
                                          'plaintext': 'aGVsbG8=', 'policy': 'Department::IT || Level::ADMIN'})
        for attrs, denied in [('Department::IT', False), ('Level::ADMIN', False), ('Department::HR', True)]:
            user = self.call('genkey', {'scheme': 'covercrypt', 'attributes': attrs})
            result = self.call('decrypt', {'secret_key': user['secret_key'], 'ciphertext': encrypted['ciphertext']}, denied)
            if not denied:
                self.assertEqual(result['plaintext'], 'aGVsbG8=')

    def test_large_authority_recovery_and_explicit_signatures(self):
        # Same dimension cardinalities as the reported 47.9-MB Base64 public
        # key failure. No external JSON, keys, environment or application DB.
        wrong_verifier = self.call('setup', {'scheme': 'ac17', 'pqc': True})['pqc_public_key']
        config = json.dumps({'dimensions': [
            {'name': f'D{i}', 'attributes': [f'v{j}' for j in range(size)]}
            for i, size in enumerate((4, 3, 6, 4, 5, 6))
        ]})
        setup = self.call('setup', {'scheme': 'covercrypt', 'config_json': config,
                                    'pqc': True, 'mode': 'hybridized'})
        self.assertEqual(setup['contract_version'], 1)
        self.assertEqual(setup['public_key_format'], 'vault-authority-sha256-v1')
        self.assertEqual(setup['public_key'], 'vault-authority-sha256:' + setup['public_key_fingerprint'])
        self.assertEqual(len(setup['public_key']), 87)
        self.assertLess(len(json.dumps(setup)), 32768)
        mount = os.environ.get('VAULT_ABE_MOUNT', 'abe').strip('/')
        recovered = api(f'{mount}/authority')['data']
        self.assertEqual(recovered, setup)
        # A lost setup response must be recovered by read, never replacement.
        self.call('setup', {'scheme': 'covercrypt', 'config_json': config,
                            'pqc': True, 'create_only': True}, denied=True, error_code=None)
        self.assertEqual(api(f'{mount}/authority')['data'], setup)
        attributes = ' '.join(f'D{i}::v0' for i in range(6))
        user = self.call('genkey', {'scheme': 'covercrypt', 'attributes': attributes})
        wrong = self.call('genkey', {'scheme': 'covercrypt', 'attributes': 'D0::v0'})
        plain = base64.b64encode(b'Large-authority isolated round trip\x00\xff').decode()
        for signed in (False, True):
            with self.subTest(large_authority=True, signed=signed):
                params = {'scheme': 'covercrypt', 'public_key': setup['public_key'],
                          'plaintext': plain, 'policy': 'D0::v0 && D1::v0', 'sign': signed}
                self.assertLess(len(json.dumps(params)), 4096)
                encrypted = self.call('encrypt', params)
                metadata = encrypted['crypto_metadata']
                self.assertEqual(metadata['scheme'], 'covercrypt')
                self.assertEqual(metadata['format'], 'hybrid-v2')
                self.assertEqual(metadata['pqc_signed'], signed)
                self.assertEqual(metadata['keyset_id'], setup['public_key_fingerprint'])
                self.assertEqual(metadata['authority_revision'], setup['revision'])
                data = {'secret_key': user['secret_key'], 'ciphertext': encrypted['ciphertext']}
                if signed:
                    data['pqc_public_key'] = setup['pqc_public_key']
                self.assertEqual(self.call('decrypt', data)['plaintext'], plain)
                data['secret_key'] = wrong['secret_key']
                self.call('decrypt', data, denied=True)
                if signed:
                    data['secret_key'] = user['secret_key']
                    data['pqc_public_key'] = wrong_verifier
                    self.call('decrypt', data, denied=True, error_code='-9')
                    data['pqc_public_key'] = setup['pqc_public_key']
                    raw = bytearray(base64.b64decode(data['ciphertext']))
                    raw[-1] ^= 1
                    data['ciphertext'] = base64.b64encode(raw).decode()
                    self.call('decrypt', data, denied=True, error_code='-4')
        self.call('encrypt', {'scheme': 'covercrypt', 'public_key': 'vault-authority-sha256:' + '0'*64,
                              'plaintext': plain, 'policy': 'D0::v0'}, denied=True, error_code=None)
        # Real plugin process reload must preserve keys and compact identity.
        api('sys/plugins/reload/backend', {'plugin': 'vault-plugin-abe'})
        self.assertEqual(api(f'{mount}/authority')['data'], setup)

    def test_json_setup_and_dimension_growth(self):
        self.call('setup', {'scheme': 'covercrypt'}, denied=True, error_code=None)
        for mode in ('classic', 'post_quantum', 'hybridized'):
            with self.subTest(mode=mode):
                setup = self.call('setup', {'scheme': 'covercrypt', 'config_json': CONFIG, 'mode': mode, 'pqc': True})
                old = self.call('genkey', {'scheme': 'covercrypt', 'attributes': 'Department::IT Level::ADMIN'})

                def encrypt(pk, policy):
                    return self.call('encrypt', {'scheme': 'covercrypt', 'public_key': pk,
                                                 'plaintext': 'aGVsbG8=', 'policy': policy})['ciphertext']

                def decrypt(key, cipher, denied=False):
                    result = self.call('decrypt', {'secret_key': key, 'ciphertext': cipher,
                                                  'pqc_public_key': setup['pqc_public_key']}, denied=denied)
                    if not denied:
                        self.assertEqual(result['plaintext'], 'aGVsbG8=')

                before = encrypt(setup['public_key'], 'Department::IT && Level::ADMIN')
                dimension = json.dumps({'name': 'E', 'attributes': ['present', 'absent']})
                grown = self.call('add_dimension', {'dimension_json': dimension})
                self.assertEqual(grown['pqc_public_key'], setup['pqc_public_key'])
                self.assertEqual(grown['mode'], mode)
                self.assertEqual(len(json.loads(grown['config_json'])['dimensions']), 3)
                decrypt(old['secret_key'], before)
                decrypt(old['secret_key'], encrypt(grown['public_key'], 'Department::IT && Level::ADMIN'))
                requires_e = encrypt(grown['public_key'], 'Department::IT && E::present')
                decrypt(old['secret_key'], requires_e, denied=True)
                new = self.call('genkey', {'scheme': 'covercrypt', 'attributes': 'Department::IT Level::ADMIN E::present'})
                decrypt(new['secret_key'], requires_e)
                decrypt(new['secret_key'], before)
                only_e = self.call('genkey', {'scheme': 'covercrypt', 'attributes': 'E::present'})
                decrypt(only_e['secret_key'], requires_e, denied=True)
                either = encrypt(grown['public_key'], 'Department::IT || E::present')
                decrypt(old['secret_key'], either)
                decrypt(only_e['secret_key'], either)
                self.call('add_dimension', {'dimension_json': dimension}, denied=True, error_code=None)
                decrypt(new['secret_key'], requires_e)


@contextmanager
def docker_service(version, runtime_base, artifact=None, raft=False):
    artifact = (artifact or ROOT / 'build/artifacts/linux/vault').resolve()
    plugin = artifact / 'vault-plugin-abe'
    library = artifact / 'libhybrid-pq-cp-abe.so'
    if not plugin.is_file() or not library.is_file():
        raise RuntimeError('Build on Linux first: make vault')
    if plugin.read_bytes()[:4] != b'\x7fELF':
        raise RuntimeError('Vault Docker service requires the Linux ELF plugin, not a Windows executable')
    base_id = hashlib.sha256(runtime_base.encode()).hexdigest()[:8]
    image = f'hcpabe-vault-test:{version}-{base_id}'
    subprocess.run(['docker', 'build', '--build-arg', f'VAULT_VERSION={version}',
                    '--build-arg', f'VAULT_RUNTIME_BASE={runtime_base}', '-t', image,
                    '-f', str(ROOT / 'plugins/vault/Dockerfile'), str(ROOT / 'plugins/vault')], check=True)
    name = 'hcpabe-vault-test-' + uuid.uuid4().hex[:12]
    original = {key: os.environ.get(key) for key in ('VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_ABE_MOUNT')}
    try:
        # No Covercrypt JSON file or environment is mounted into the service.
        command = ['docker', 'run', '-d', '--name', name,
                   '-p', '127.0.0.1::8200',
                   '--mount', f'type=bind,source={artifact},target=/vault/plugins,readonly', image]
        if raft:
            command += ['vault', 'server', '-config=/vault/config/server.hcl',
                        '-config=/vault/config/raft.hcl']
        subprocess.run(command, check=True)
        port = subprocess.check_output(['docker', 'port', name, '8200/tcp'], text=True).strip().rsplit(':', 1)[1]
        address = f'http://127.0.0.1:{port}'
        os.environ.update(VAULT_ADDR=address, VAULT_TOKEN='root', VAULT_ABE_MOUNT='abe')
        deadline = time.monotonic() + 45
        while True:
            try:
                api('sys/seal-status')
                break
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Vault service did not become ready')
                time.sleep(0.5)
        if raft:
            # Only this disposable single-node fixture is initialized/unsealed.
            # Keep shares/root token in memory; never print or persist them.
            initialized = api('sys/init', {'secret_shares': 1, 'secret_threshold': 1})
            api('sys/unseal', {'key': initialized['keys'][0]})
            os.environ['VAULT_TOKEN'] = initialized['root_token']
            del initialized
            deadline = time.monotonic() + 45
            while True:
                try:
                    api('sys/health')
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Raft fixture did not elect an active node')
                    time.sleep(0.5)
        checksum = hashlib.sha256(plugin.read_bytes()).hexdigest()
        api('sys/plugins/catalog/secret/vault-plugin-abe', {'sha256': checksum, 'command': 'vault-plugin-abe'})
        api('sys/mounts/abe', {'type': 'vault-plugin-abe'})
        print(f'Vault service: {address}, plugin SHA256: {checksum}', flush=True)
        yield
    finally:
        log = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
        logpath = ROOT / 'build/logs/vault-service.log'
        logpath.parent.mkdir(parents=True, exist_ok=True)
        logpath.write_text(log.stdout + log.stderr)
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--raft', action='store_true', help='Use isolated real Raft storage with default entry/request limits (requires --docker)')
    parser.add_argument('--vault-version', default='2.0.4')
    parser.add_argument('--runtime-base', default=os.environ.get('VAULT_RUNTIME_BASE', 'ubuntu:24.04'))
    parser.add_argument('--artifact-dir', type=Path, help='Test an extracted release package instead of build output')
    args = parser.parse_args()
    if args.raft and not args.docker:
        parser.error('--raft requires --docker; it never initializes an external Vault')

    def suite():
        return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(VaultHTTPTests)).wasSuccessful()

    if args.docker:
        with docker_service(args.vault_version, args.runtime_base, args.artifact_dir, args.raft):
            return suite()
    return suite()


if __name__ == '__main__':
    raise SystemExit(0 if run() else 1)
