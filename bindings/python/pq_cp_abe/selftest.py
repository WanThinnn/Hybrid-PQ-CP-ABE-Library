"""Complete runnable self-test of the 33 native C exports.

Runs exclusively in TemporaryDirectory. Instrumented calls record which DLL
symbols Python actually invoked (not merely whether the symbols were declared).
"""
import base64
import contextlib
import ctypes
import io
import os
from pathlib import Path
import tempfile
import unittest

from . import api, extended_api, native, __version__

EXPORTS = """aes_gcm_decrypt aes_gcm_encrypt freeBuffer generateSecretKey generateSecretKey_with_scheme
getErrorMessage getVersion hybrid_cpabe_covercrypt_add_attribute hybrid_cpabe_covercrypt_add_attributeBuffer
hybrid_cpabe_covercrypt_add_dimension hybrid_cpabe_covercrypt_add_dimensionBuffer hybrid_cpabe_decrypt
hybrid_cpabe_decryptBuffer hybrid_cpabe_decryptBuffer_and_verify hybrid_cpabe_decrypt_and_verify
hybrid_cpabe_encrypt hybrid_cpabe_encryptBuffer hybrid_cpabe_encryptBuffer_and_sign
hybrid_cpabe_encryptBuffer_and_sign_with_scheme hybrid_cpabe_encryptBuffer_with_scheme
hybrid_cpabe_encrypt_and_sign hybrid_cpabe_encrypt_and_sign_with_scheme hybrid_cpabe_encrypt_with_scheme
hybrid_cpabe_genkeyBuffer_with_scheme hybrid_cpabe_setupBuffer_with_pqc_scheme
hybrid_cpabe_setupBuffer_with_scheme hybrid_cpabe_setup_with_pqc hybrid_cpabe_setup_with_pqc_scheme
ml_dsa_87_generate_keypair ml_dsa_87_sign ml_dsa_87_verify setup setup_with_scheme""".split()

def _read_key(file):
    content = Path(file).read_text(encoding="utf-8")
    body = "".join(line.strip() for line in content.splitlines()
                   if line.strip() and not line.startswith("-----"))
    return base64.b64decode(body)

@contextlib.contextmanager
def _track_exports():
    original = {name: getattr(native, name) for name in EXPORTS}
    called = set()
    try:
        for name, fn in original.items():
            def wrapped(*args, _name=name, _fn=fn):
                called.add(_name)
                return _fn(*args)
            wrapped.__name__ = name
            wrapped.argtypes = fn.argtypes
            wrapped.restype = fn.restype
            setattr(native, name, wrapped)
        yield called
    finally:
        for name, fn in original.items():
            setattr(native, name, fn)

@contextlib.contextmanager
def _covercrypt_settings(config_file):
    keys = ("HCPABE_COVERCRYPT_CONFIG", "HCPABE_COVERCRYPT_MODE")
    old = {key: os.environ.get(key) for key in keys}
    os.environ[keys[0]] = str(config_file)
    os.environ[keys[1]] = "hybridized"
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

class CompleteNativeSelfTest(unittest.TestCase):
    def test_all_33_exports(self):
        self.assertEqual(len(EXPORTS), 33)
        for symbol in EXPORTS:
            func = getattr(native, symbol)
            self.assertIsNotNone(func.argtypes, symbol)
            if symbol == "freeBuffer":
                self.assertIsNone(func.restype)
            else:
                self.assertIsNotNone(func.restype, symbol)
        with tempfile.TemporaryDirectory(prefix="pq-cp-abe-test-") as temp:
            root = Path(temp)
            with _track_exports() as called:
                # Utilities / memory release
                self.assertEqual(extended_api.get_version(), __version__)
                self.assertTrue(extended_api.get_error_message(-5))
                native.freeBuffer(ctypes.POINTER(ctypes.c_ubyte)())

                # Standalone AES-256-GCM + authenticated failure
                key, nonce = bytes(range(32)), bytes(range(12))
                ct = extended_api.aes_gcm_encrypt(key, nonce, b"plaintext", b"aad")
                self.assertEqual(extended_api.aes_gcm_decrypt(key, nonce, ct, b"aad"), b"plaintext")
                with self.assertRaises(RuntimeError):
                    extended_api.aes_gcm_decrypt(key, nonce, ct, b"wrong-aad")
                long_nonce = bytes(range(24, 48))
                long_ct = extended_api.aes_gcm_encrypt(key, long_nonce, b"plaintext", b"aad")
                self.assertEqual(extended_api.aes_gcm_decrypt(key, long_nonce, long_ct, b"aad"), b"plaintext")
                with self.assertRaises(RuntimeError):
                    extended_api.aes_gcm_decrypt(key, nonce, long_ct, b"aad")
                with self.assertRaises(ValueError):
                    extended_api.aes_gcm_encrypt(key, nonce[:11], b"plaintext")
                with self.assertRaises(ValueError):
                    extended_api.aes_gcm_decrypt(key, nonce[:11], ct)
                print("  PASS AES-GCM")

                # Standalone ML-DSA-87 including tamper detection.
                pk_sig, sk_sig = extended_api.ml_dsa_87_generate_keypair()
                signature = extended_api.ml_dsa_87_sign(b"message", sk_sig)
                self.assertTrue(extended_api.ml_dsa_87_verify(b"message", signature, pk_sig))
                self.assertFalse(extended_api.ml_dsa_87_verify(b"tampered", signature, pk_sig))
                print("  PASS ML-DSA-87")

                data = b"Full Python C ABI self-test"
                policy = "admin and it"

                # Legacy file operations (default AC17) and default PQC file calls.
                legacy = root / "legacy"
                legacy.mkdir()
                self.assertEqual(api.call_setup(str(legacy), scheme=api.CPABE_SCHEME_AC17), 0)
                msk = legacy / "cpabe_msk.key"
                pk = legacy / "cpabe_pk.key"
                user = legacy / "user.key"
                plain = legacy / "plain.bin"
                plain.write_bytes(data)
                cipher = legacy / "enc.bin"
                recover = legacy / "recover.bin"
                self.assertEqual(api.call_generate_secret_key(str(msk), "admin it", str(user), scheme=api.CPABE_SCHEME_AC17), 0)
                self.assertEqual(api.call_hybrid_cpabe_encrypt(str(pk), str(plain), policy, str(cipher), scheme=api.CPABE_SCHEME_AC17), 0)
                self.assertEqual(api.call_hybrid_cpabe_decrypt(str(user), str(cipher), str(recover)), 0)
                self.assertEqual(recover.read_bytes(), data)
                key_pk = _read_key(pk)
                key_sk = _read_key(user)
                buffer_ct = api.call_hybrid_cpabe_encryptBuffer(key_pk, data, policy, scheme=api.CPABE_SCHEME_AC17)
                self.assertEqual(api.call_hybrid_cpabe_decryptBuffer(key_sk, buffer_ct), data)

                legacy_pqc = root / "legacy-pqc"
                legacy_pqc.mkdir()
                self.assertEqual(api.call_hybrid_cpabe_setup_with_pqc(str(legacy_pqc), scheme=api.CPABE_SCHEME_AC17), 0)
                pqc_user = legacy_pqc / "user.key"
                self.assertEqual(api.call_generate_secret_key(
                    str(legacy_pqc / "cpabe_msk.key"), "admin it", str(pqc_user), scheme=api.CPABE_SCHEME_AC17), 0)
                pqc_plain = legacy_pqc / "plain.bin"
                pqc_plain.write_bytes(data)
                pqc_cipher = legacy_pqc / "signed.bin"
                pqc_recovered = legacy_pqc / "recovered.bin"
                pqc_public = legacy_pqc / "pqc_pk.key"
                pqc_private = legacy_pqc / "pqc_sk.key"
                self.assertEqual(api.call_hybrid_cpabe_encrypt_and_sign(
                    str(legacy_pqc / "cpabe_pk.key"), str(pqc_private), str(pqc_plain),
                    policy, str(pqc_cipher), scheme=api.CPABE_SCHEME_AC17), 0)
                self.assertEqual(api.call_hybrid_cpabe_decrypt_and_verify(
                    str(pqc_user), str(pqc_public), str(pqc_cipher), str(pqc_recovered)), 0)
                self.assertEqual(pqc_recovered.read_bytes(), data)
                signed = api.call_hybrid_cpabe_encryptBuffer_and_sign(
                    _read_key(legacy_pqc / "cpabe_pk.key"), _read_key(pqc_private), data, policy, scheme=api.CPABE_SCHEME_AC17)
                self.assertEqual(api.call_hybrid_cpabe_decryptBuffer_and_verify(
                    _read_key(pqc_user), _read_key(pqc_public), signed), data)
                print("  PASS legacy AC17 file / buffer / PQC")

                for name, scheme in (("AC17", 0), ("TKN20", 1), ("CoverCrypt", 2)):
                    directory = root / name
                    directory.mkdir()
                    config = directory / "config.json"
                    config.write_text('{"dimensions":[{"name":"admin","attributes":["present","absent"]},'
                                      '{"name":"it","attributes":["present","absent"]}]}', encoding="utf-8")
                    settings = _covercrypt_settings(config) if scheme == 2 else contextlib.nullcontext()
                    with settings:
                        scheme_options = {} if scheme == api.CPABE_SCHEME_COVERCRYPT else {"scheme": scheme}
                        # Setup and keygen from file, also signing.
                        self.assertEqual(api.call_hybrid_cpabe_setup_with_pqc_scheme(
                            str(directory), **scheme_options), 0)
                        master = directory / "cpabe_msk.key"
                        public = directory / "cpabe_pk.key"
                        userkey = directory / "user.key"
                        self.assertEqual(api.call_generate_secret_key_with_scheme(
                            str(master), "admin it", str(userkey), **scheme_options), 0)
                        message = directory / "message.bin"
                        message.write_bytes(data)
                        out = directory / "ciphertext.bin"
                        decoded = directory / "decoded.bin"
                        self.assertEqual(api.call_hybrid_cpabe_encrypt_with_scheme(
                            str(public), str(message), policy, str(out), **scheme_options), 0)
                        self.assertEqual(api.call_hybrid_cpabe_decrypt(
                            str(userkey), str(out), str(decoded)), 0)
                        self.assertEqual(decoded.read_bytes(), data)
                        self.assertEqual(api.call_hybrid_cpabe_encrypt_and_sign_with_scheme(
                            str(public), str(directory / "pqc_sk.key"), str(message),
                            policy, str(out), **scheme_options), 0)
                        self.assertEqual(api.call_hybrid_cpabe_decrypt_and_verify(
                            str(userkey), str(directory / "pqc_pk.key"), str(out), str(decoded)), 0)
                        self.assertEqual(decoded.read_bytes(), data)

                        # Scheme-aware in-memory setup, keygen, encrypt/decrypt/sign/verify.
                        pk_buffer, msk_buffer = extended_api.setup_buffer(**scheme_options)
                        sk_buffer = extended_api.genkey_buffer(msk_buffer, "admin it", **scheme_options)
                        ciphertext = api.call_hybrid_cpabe_encryptBuffer_with_scheme(
                            pk_buffer, data, policy, **scheme_options)
                        self.assertEqual(ciphertext[1], scheme)
                        self.assertEqual(api.call_hybrid_cpabe_decryptBuffer(sk_buffer, ciphertext), data)
                        signed_buffer = api.call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
                            pk_buffer, _read_key(directory / "pqc_sk.key"), data, policy, **scheme_options)
                        self.assertEqual(api.call_hybrid_cpabe_decryptBuffer_and_verify(
                            sk_buffer, _read_key(directory / "pqc_pk.key"), signed_buffer), data)
                        abe_pk, abe_msk, pqc_pk, pqc_sk = extended_api.setup_buffer_with_pqc(**scheme_options)
                        self.assertTrue(abe_pk and abe_msk and pqc_pk and pqc_sk)
                        print(f"  PASS {name} scheme / file / buffer / signed")

                # CoverCrypt authority growth: both file and buffer variants.
                authority = root / "authority"
                authority.mkdir()
                config = authority / "config.json"
                config.write_text('{"dimensions":[{"name":"A","attributes":["present"]}]}',
                                  encoding="utf-8")
                with _covercrypt_settings(config):
                    pub, master = extended_api.setup_buffer(2)
                    pub, master = extended_api.covercrypt_add_dimension_buffer(
                        master, '{"name":"E","attributes":["present"]}')
                    pub, master = extended_api.covercrypt_add_attribute_buffer(master, "E", "added")
                    subkey = extended_api.genkey_buffer(master, "A::present && E::added", 2)
                    encrypted = api.call_hybrid_cpabe_encryptBuffer_with_scheme(
                        pub, data, "A::present && E::added", 2)
                    self.assertEqual(api.call_hybrid_cpabe_decryptBuffer(subkey, encrypted), data)
                    initial = str(authority / "initial")
                    self.assertEqual(api.call_setup_with_scheme(initial, 2), 0)
                    first = str(authority / "growth1")
                    second = str(authority / "growth2")
                    self.assertEqual(extended_api.covercrypt_add_dimension(
                        initial + "_msk.key", '{"name":"E","attributes":["present"]}', first), 0)
                    self.assertEqual(extended_api.covercrypt_add_attribute(
                        first + "_msk.key", "E", "added", second), 0)
                    self.assertTrue(Path(second + "_pk.key").is_file())
                    self.assertTrue(Path(second + "_msk.key").is_file())
                print("  PASS CoverCrypt growth / file / buffer")

                missing = set(EXPORTS) - called
                for symbol in EXPORTS:
                    print(f"  [{'PASS' if symbol in called else 'MISS'}] {symbol}")
                self.assertFalse(missing, f"Not exercised: {sorted(missing)}")
                print(f"  PASS: {len(called)}/{len(EXPORTS)} C symbols actually invoked")


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CompleteNativeSelfTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
