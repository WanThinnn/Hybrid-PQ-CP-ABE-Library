"""Real CLI tests for extending an authority without invalidating old keys."""
import json
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


@unittest.skipUnless(CLI.is_file(), 'Build the CLI first')
class CovercryptGrowthTests(unittest.TestCase):
    def test_public_buffer_growth_in_all_modes(self):
        import ctypes as c
        import sys
        sys.path.insert(0, str(ROOT / 'benchmark'))
        from benchmark_full import COVERCRYPT, Native, find_lib

        native = Native(find_lib(ROOT, None))
        out = [c.POINTER(native.P8), c.POINTER(c.c_size_t)] * 2
        dimension = native.lib.hybrid_cpabe_covercrypt_add_dimensionBuffer
        attribute = native.lib.hybrid_cpabe_covercrypt_add_attributeBuffer
        dimension.argtypes = [native.P8, c.c_size_t, c.c_char_p, *out]
        attribute.argtypes = [native.P8, c.c_size_t, c.c_char_p, c.c_char_p, c.c_char_p, *out]
        dimension.restype = attribute.restype = c.c_int

        def grow(function, master, *args):
            pk, msk = native.P8(), native.P8()
            pkl, mskl = c.c_size_t(), c.c_size_t()
            status = function(native.arr(master), len(master), *args,
                              c.byref(pk), c.byref(pkl), c.byref(msk), c.byref(mskl))
            public, secret = native.take(pk, pkl.value), native.take(msk, mskl.value)
            native.check(status, 'grow authority buffer')
            return public, secret

        names = ('HCPABE_COVERCRYPT_CONFIG', 'HCPABE_COVERCRYPT_MODE')
        original = {name: os.environ.get(name) for name in names}
        try:
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / 'config.json'
                config.write_text('{"dimensions":[{"name":"A","attributes":["present"]}]}')
                os.environ[names[0]] = str(config)
                for mode in ('classic', 'post_quantum', 'hybridized'):
                    with self.subTest(mode=mode):
                        os.environ[names[1]] = mode
                        pk, msk = native.setup_buffer(COVERCRYPT)
                        user = native.genkey_buffer(msk, 'A::present', COVERCRYPT)
                        before = native.encrypt_buffer(pk, b'old data', 'A::present', COVERCRYPT)
                        pk, msk = grow(dimension, msk, b'{"name":"E","attributes":["present"]}')
                        pk, msk = grow(attribute, msk, b'E', b'added', None)
                        after = native.encrypt_buffer(pk, b'new data', 'A::present && E::added', COVERCRYPT)
                        with self.assertRaisesRegex(RuntimeError, r'\(-3\)'):
                            native.decrypt_buffer(user, after)
                        updated = native.genkey_buffer(msk, 'A::present && E::added', COVERCRYPT)
                        self.assertEqual(native.decrypt_buffer(updated, after), b'new data')
                        self.assertEqual(native.decrypt_buffer(updated, before), b'old data')
                        self.assertEqual(native.decrypt_buffer(user, before), b'old data')
                        old_policy = native.encrypt_buffer(pk, b'same rights', 'A::present', COVERCRYPT)
                        self.assertEqual(native.decrypt_buffer(user, old_policy), b'same rights')
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def call(self, *args, env, allowed=True):
        output = Path(args[-1]) if args[0] == 'decrypt' else None
        if output is not None:
            output.unlink(missing_ok=True)
        result = subprocess.run([str(CLI), *map(str, args)], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode == 0, allowed, result.stdout + result.stderr)
        if output is not None:
            self.assertEqual(output.is_file(), allowed, 'Decrypt output does not match its authorization result')
        return result

    def test_add_e_preserves_a_to_d_and_does_not_grant_e_to_old_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.json'
            config.write_text(json.dumps({'dimensions': [
                {'name': name, 'attributes': ['present', 'absent']} for name in 'ABCD'
            ]}))
            env = dict(os.environ, HCPABE_COVERCRYPT_CONFIG=str(config), HCPABE_COVERCRYPT_MODE='hybridized')
            old, grown = root / 'old', root / 'grown'
            self.call('setup', '--scheme', 'covercrypt', '--pqc', old, env=env)
            old_msk, old_pk = Path(str(old) + '_msk.key'), Path(str(old) + '_pk.key')
            user = root / 'user-ab.key'
            self.call('genkey', '--scheme', 'covercrypt', old_msk, 'A::present && B::present', user, env=env)
            original = {path: path.read_bytes() for path in (old_msk, old_pk, user)}
            plain, before, after, recovered = root / 'plain', root / 'before.enc', root / 'after.enc', root / 'out'
            plain.write_bytes(b'Existing encrypted data\x00\xff')
            self.call('encrypt', '--scheme', 'covercrypt', old_pk, plain, 'A::present && B::present', before, env=env)
            self.call('add_dimension', '--scheme', 'covercrypt', old_msk,
                      ROOT / 'scripts/covercrypt-add-e.json', grown, env=env)
            new_msk, new_pk = Path(str(grown) + '_msk.key'), Path(str(grown) + '_pk.key')
            self.assertTrue(new_msk.is_file() and new_pk.is_file())
            for path, value in original.items():
                self.assertEqual(path.read_bytes(), value, 'Authority growth modified an input key')
            self.call('decrypt', user, before, recovered, env=env)
            self.assertEqual(recovered.read_bytes(), plain.read_bytes())
            self.call('encrypt', '--scheme', 'covercrypt', new_pk, plain, 'A::present && B::present', after, env=env)
            self.call('decrypt', user, after, recovered, env=env)
            self.call('encrypt', '--scheme', 'covercrypt', new_pk, plain, 'A::present && E::present', after, env=env)
            self.call('decrypt', user, after, recovered, env=env, allowed=False)
            new_user = root / 'user-abe.key'
            self.call('genkey', '--scheme', 'covercrypt', new_msk,
                      'A::present && B::present && E::present', new_user, env=env)
            self.call('decrypt', new_user, after, recovered, env=env)
            self.call('decrypt', new_user, before, recovered, env=env)
            # Existing signing keys remain usable: growth updates only the ABE authority.
            self.call('encrypt', '--scheme', 'covercrypt', '--pqc', new_pk, str(old) + '_pqc_sk.key',
                      plain, 'A::present && E::present', after, env=env)
            self.call('decrypt', '--pqc', new_user, str(old) + '_pqc_pk.key', after, recovered, env=env)
            self.assertEqual(recovered.read_bytes(), plain.read_bytes())
            self.call('encrypt', '--scheme', 'covercrypt', new_pk, plain, 'A::present || E::present', after, env=env)
            self.call('decrypt', user, after, recovered, env=env)
            # Duplicate dimensions and reused output names fail without touching files.
            pair = {path: path.read_bytes() for path in (new_msk, new_pk)}
            self.call('add_dimension', '--scheme', 'covercrypt', old_msk,
                      ROOT / 'scripts/covercrypt-add-e.json', grown, env=env, allowed=False)
            self.call('add_dimension', '--scheme', 'covercrypt', new_msk,
                      ROOT / 'scripts/covercrypt-add-e.json', root / 'invalid', env=env, allowed=False)
            self.assertFalse((root / 'invalid_msk.key').exists())
            for path, value in pair.items():
                self.assertEqual(path.read_bytes(), value)

    def test_add_attribute_honors_hierarchy_and_preserves_old_rights(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.json'
            config.write_text(json.dumps({'dimensions': [
                {'name': 'Level', 'attributes': ['USER', 'ADMIN'], 'hierarchical': True}
            ]}))
            env = dict(os.environ, HCPABE_COVERCRYPT_CONFIG=str(config), HCPABE_COVERCRYPT_MODE='hybridized')
            old, grown = root / 'old', root / 'grown'
            self.call('setup', '--scheme', 'covercrypt', old, env=env)
            old_msk = Path(str(old) + '_msk.key')
            user, new_user = root / 'admin.key', root / 'super.key'
            self.call('genkey', '--scheme', 'covercrypt', old_msk, 'Level::ADMIN', user, env=env)
            original = old_msk.read_bytes()
            self.call('add_attribute', '--scheme', 'covercrypt', old_msk, 'Level', 'SUPER', grown, 'ADMIN', env=env)
            self.assertEqual(old_msk.read_bytes(), original)
            new_msk, new_pk = str(grown) + '_msk.key', str(grown) + '_pk.key'
            self.call('genkey', '--scheme', 'covercrypt', new_msk, 'Level::SUPER', new_user, env=env)
            plain, cipher, recovered = root / 'plain', root / 'cipher', root / 'out'
            plain.write_bytes(b'Hierarchy semantics come from upstream')
            self.call('encrypt', '--scheme', 'covercrypt', new_pk, plain, 'Level::USER', cipher, env=env)
            self.call('decrypt', user, cipher, recovered, env=env)
            self.call('decrypt', new_user, cipher, recovered, env=env)
            self.call('encrypt', '--scheme', 'covercrypt', new_pk, plain, 'Level::SUPER', cipher, env=env)
            self.call('decrypt', user, cipher, recovered, env=env, allowed=False)
            self.call('decrypt', new_user, cipher, recovered, env=env)
            self.assertEqual(recovered.read_bytes(), plain.read_bytes())


if __name__ == '__main__':
    unittest.main()
