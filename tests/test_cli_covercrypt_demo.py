"""Smoke-test the documented CoverCrypt CLI fixture and compiled version."""
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SYSTEM = platform.system()
TARGET = {'Windows': 'windows', 'Darwin': 'macos'}.get(SYSTEM, 'linux')
CLI = ROOT / 'build/artifacts' / TARGET / ('main.exe' if SYSTEM == 'Windows' else 'main')


@unittest.skipUnless(CLI.is_file(), 'Build the CLI with make first')
class CovercryptDemoTests(unittest.TestCase):
    def call(self, *args, env=None):
        return subprocess.run([str(CLI), *map(str, args)], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=30)

    def test_help_documents_configuration_and_version_matches_source(self):
        help = self.call('--help')
        self.assertEqual(help.returncode, 0, help.stderr)
        for text in ('HCPABE_COVERCRYPT_CONFIG', 'HCPABE_COVERCRYPT_MODE',
                     'scripts/covercrypt-demo.json', '.env', 'CMD:', 'PowerShell:', 'Linux/macOS:'):
            self.assertIn(text, help.stdout)
        version = (ROOT / 'VERSION').read_text().strip()
        self.assertEqual(self.call('--version').stdout.strip(), f'Hybrid PQ-CP-ABE Library v{version}')

    def test_missing_configuration_has_an_actionable_error(self):
        env = dict(os.environ)
        env.pop('HCPABE_COVERCRYPT_CONFIG', None)
        with tempfile.TemporaryDirectory() as directory:
            result = self.call('setup', '--scheme', 'covercrypt', Path(directory) / 'demo', env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('HCPABE_COVERCRYPT_CONFIG', result.stderr)
            self.assertIn('--help', result.stderr)

    def test_demo_roundtrips_with_and_without_signatures(self):
        env = dict(os.environ, HCPABE_COVERCRYPT_CONFIG=str(ROOT / 'scripts/covercrypt-demo.json'),
                   HCPABE_COVERCRYPT_MODE='hybridized')
        policy = 'Department::IT && Level::ADMIN'
        for signed in (False, True):
            with self.subTest(signed=signed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prefix, user = root / 'demo', root / 'user.key'
                plain, cipher, recovered = root / 'plain.txt', root / 'data.enc', root / 'recovered.txt'
                plain.write_bytes(b'Covercrypt demo\x00roundtrip\xff')
                flag = ['--pqc'] if signed else []
                commands = [
                    ['setup', '--scheme', 'covercrypt', *flag, prefix],
                    ['genkey', '--scheme', 'covercrypt', str(prefix) + '_msk.key', policy, user],
                    ['encrypt', '--scheme', 'covercrypt', *flag, str(prefix) + '_pk.key',
                     *([str(prefix) + '_pqc_sk.key'] if signed else []), plain, policy, cipher],
                    ['decrypt', *flag, user,
                     *([str(prefix) + '_pqc_pk.key'] if signed else []), cipher, recovered],
                ]
                for command in commands:
                    result = self.call(*command, env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(recovered.read_bytes(), plain.read_bytes())

    def test_omitting_a_dimension_does_not_grant_its_attributes(self):
        env = dict(os.environ, HCPABE_COVERCRYPT_CONFIG=str(ROOT / 'scripts/covercrypt-demo.json'),
                   HCPABE_COVERCRYPT_MODE='hybridized')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix, plain, cipher = root / 'demo', root / 'plain.txt', root / 'data.enc'
            plain.write_bytes(b'Only IT administrators may decrypt this')
            result = self.call('setup', '--scheme', 'covercrypt', prefix, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = self.call('encrypt', '--scheme', 'covercrypt', str(prefix) + '_pk.key', plain,
                               'Department::IT && Level::ADMIN', cipher, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            cases = [('Department::IT && Level::ADMIN', True), ('Department::IT', False),
                     ('Department::HR', False), ('Department::HR && Level::ADMIN', False)]
            for index, (attributes, allowed) in enumerate(cases):
                with self.subTest(attributes=attributes):
                    key, recovered = root / f'user-{index}.key', root / f'out-{index}.txt'
                    result = self.call('genkey', '--scheme', 'covercrypt', str(prefix) + '_msk.key',
                                       attributes, key, env=env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = self.call('decrypt', key, cipher, recovered, env=env)
                    self.assertEqual(result.returncode == 0, allowed, result.stdout + result.stderr)
                    if allowed:
                        self.assertEqual(recovered.read_bytes(), plain.read_bytes())
            result = self.call('encrypt', '--scheme', 'covercrypt', str(prefix) + '_pk.key', plain,
                               'Department::IT || Level::ADMIN', cipher, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            for index, (attributes, _) in enumerate(cases):
                with self.subTest(or_policy=True, attributes=attributes):
                    result = self.call('decrypt', root / f'user-{index}.key', cipher,
                                       root / f'or-out-{index}.txt', env=env)
                    self.assertEqual(result.returncode == 0, index in (0, 1, 3), result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
