"""Modern API integration and native-buffer ownership regression checks."""
import contextlib
import ctypes
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pq_cp_abe as abe
from pq_cp_abe import modern_api
from pq_cp_abe.selftest import _covercrypt_settings


class ModernApiTests(unittest.TestCase):
    def test_roundtrip_signed_and_files_all_schemes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text('{"dimensions":[{"name":"admin","attributes":["present","absent"]},'
                              '{"name":"it","attributes":["present","absent"]}]}', encoding="utf-8")
            with _covercrypt_settings(config):
                for scheme in abe.Scheme:
                    with self.subTest(scheme=scheme):
                        keys = abe.setup_with_signing(scheme=scheme)
                        secret_key = abe.generate_secret_key(keys.master_secret_key, "admin it", scheme=scheme)
                        for message in (b"", b"\x00Hello\xff"):
                            ciphertext = abe.encrypt(keys.public_key, message, "admin and it", scheme=scheme)
                            self.assertEqual(abe.decrypt(secret_key, ciphertext), message)
                        signed = abe.encrypt_and_sign(keys.public_key, keys.signing_key, b"signed",
                                                       "admin and it", scheme=scheme)
                        self.assertEqual(abe.decrypt_and_verify(secret_key, keys.verification_key, signed), b"signed")
                        bad = bytearray(signed)
                        bad[-1] ^= 1
                        with self.assertRaises(abe.AbeError) as raised:
                            abe.decrypt_and_verify(secret_key, keys.verification_key, bytes(bad))
                        self.assertLess(raised.exception.code, 0)

                        directory = root / scheme.name
                        directory.mkdir()
                        abe.setup_files_with_signing(directory, scheme=scheme)
                        user = directory / "user.key"
                        abe.generate_secret_key_file(directory / "cpabe_msk.key", "admin it", user, scheme=scheme)
                        plain, cipher, recovered = [directory / name for name in ("plain", "cipher", "recovered")]
                        plain.write_bytes(b"file payload")
                        abe.encrypt_file(directory / "cpabe_pk.key", plain, "admin and it", cipher, scheme=scheme)
                        abe.decrypt_file(user, cipher, recovered)
                        self.assertEqual(recovered.read_bytes(), b"file payload")
                        abe.encrypt_and_sign_file(directory / "cpabe_pk.key", directory / "pqc_sk.key",
                                                  plain, "admin and it", cipher, scheme=scheme)
                        abe.decrypt_and_verify_file(user, directory / "pqc_pk.key", cipher, recovered)
                        self.assertEqual(recovered.read_bytes(), b"file payload")

    def test_setup_and_legacy_compatibility(self):
        keys = abe.setup(scheme=abe.Scheme.AC17)
        pk, msk = keys
        self.assertEqual(pk, keys.public_key)
        key = abe.generate_secret_key(msk, "admin", scheme=abe.Scheme.AC17)
        ct = abe.call_hybrid_cpabe_encryptBuffer(pk, b"legacy", "admin", scheme=abe.Scheme.AC17)
        self.assertEqual(abe.decrypt(key, ct), b"legacy")
        ct = abe.encrypt(pk, b"modern", "admin", scheme=abe.Scheme.AC17)
        self.assertEqual(abe.call_hybrid_cpabe_decryptBuffer(key, ct), b"modern")
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertIsNone(abe.setup_files(Path(temporary), scheme=abe.Scheme.AC17))
        self.assertEqual(output.getvalue(), "")

    def test_error_mapping_and_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(abe.AbeError) as raised:
                abe.decrypt_file(Path(temporary) / "missing", "missing", "unused")
            self.assertEqual(raised.exception.code, -1)
        with self.assertRaises(TypeError):
            abe.encrypt("not bytes", b"message", "admin")
        with self.assertRaises(ValueError):
            abe.setup(scheme=999)
        with self.assertRaises(ValueError):
            abe.generate_secret_key(b"key", "admin\0it")
        for code, error in ((-3, abe.PolicyMismatchError), (-9, abe.SignatureInvalidError)):
            with self.assertRaises(error):
                modern_api._check(code, "test")

    def test_partial_native_output_is_freed_on_error(self):
        owned = (ctypes.c_ubyte * 3)(1, 2, 3)

        def failing(pointer_out, length_out, scheme):
            ctypes.cast(pointer_out, ctypes.POINTER(modern_api.c_ubyte_p))[0] = ctypes.cast(owned, modern_api.c_ubyte_p)
            ctypes.cast(length_out, ctypes.POINTER(ctypes.c_size_t))[0] = 3
            return -4

        with patch.object(modern_api.abe_lib, "hybrid_cpabe_setupBuffer_with_scheme", failing), \
             patch.object(modern_api.abe_lib, "freeBuffer") as free:
            with self.assertRaises(abe.AbeError):
                modern_api._outputs("hybrid_cpabe_setupBuffer_with_scheme", scheme=abe.Scheme.AC17)
            free.assert_called_once()


if __name__ == "__main__":
    unittest.main()
