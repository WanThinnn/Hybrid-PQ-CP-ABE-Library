"""Regression checks for the Python C ABI declarations and extended wrappers."""
import os
import sys
from tempfile import TemporaryDirectory
from pathlib import Path
import unittest

PYTHON = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PYTHON))
import pq_cp_abe as abe
from pq_cp_abe._native import abe_lib

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

class Coverage(unittest.TestCase):
    def test_ctypes_declarations(self):
        self.assertEqual(len(EXPORTS), 33)
        self.assertIs(abe.native, abe_lib)
        for name in EXPORTS:
            with self.subTest(name=name):
                fn = getattr(abe_lib, name)
                self.assertIsNotNone(fn.argtypes)
                self.assertIsNone(fn.restype) if name == "freeBuffer" else self.assertIsNotNone(fn.restype)

    def test_extended_python_api(self):
        for name in (
            "setup_buffer", "setup_buffer_with_pqc", "genkey_buffer",
            "covercrypt_add_attribute", "covercrypt_add_dimension",
            "covercrypt_add_attribute_buffer", "covercrypt_add_dimension_buffer",
            "ml_dsa_87_generate_keypair", "ml_dsa_87_sign", "ml_dsa_87_verify",
            "aes_gcm_encrypt", "aes_gcm_decrypt", "get_version", "get_error_message"
        ):
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(abe, name)))

    def test_ml_dsa(self):
        pk, sk = abe.ml_dsa_87_generate_keypair()
        self.assertEqual(len(pk), 2592)
        self.assertEqual(len(sk), 4896)
        sig = abe.ml_dsa_87_sign(b"sample", sk)
        self.assertTrue(abe.ml_dsa_87_verify(b"sample", sig, pk))
        self.assertFalse(abe.ml_dsa_87_verify(b"other", sig, pk))

    def test_aes(self):
        key = bytes(range(32))
        iv = bytes(range(12))
        ciphertext = abe.aes_gcm_encrypt(key, iv, b"payload", b"aad")
        self.assertEqual(abe.aes_gcm_decrypt(key, iv, ciphertext, b"aad"), b"payload")
        with self.assertRaises(RuntimeError):
            abe.aes_gcm_decrypt(key, iv, ciphertext, b"wrong")

    def test_setup_buffers(self):
        pk, msk = abe.setup_buffer(abe.CPABE_SCHEME_AC17)
        sk = abe.genkey_buffer(msk, "admin it", abe.CPABE_SCHEME_AC17)
        ct = abe.call_hybrid_cpabe_encryptBuffer_with_scheme(
            pk, b"payload", "admin and it", abe.CPABE_SCHEME_AC17)
        self.assertEqual(abe.call_hybrid_cpabe_decryptBuffer(sk, ct), b"payload")

    def test_pqc_setup_buffers(self):
        pk, msk, sig_pk, sig_sk = abe.setup_buffer_with_pqc()
        self.assertTrue(pk and msk)
        import base64
        self.assertEqual(len(base64.b64decode(sig_pk)), 2592)
        self.assertEqual(len(base64.b64decode(sig_sk)), 4896)


    def test_covercrypt_authority_growth_buffers_and_files(self):
        original_config = os.environ.get("HCPABE_COVERCRYPT_CONFIG")
        original_mode = os.environ.get("HCPABE_COVERCRYPT_MODE")
        try:
            with TemporaryDirectory() as directory:
                root = Path(directory)
                config = root / "config.json"
                config.write_text('{"dimensions":[{"name":"A","attributes":["present"]}]}', encoding="utf-8")
                os.environ["HCPABE_COVERCRYPT_CONFIG"] = str(config)
                os.environ["HCPABE_COVERCRYPT_MODE"] = "hybridized"
                public, master = abe.setup_buffer(abe.CPABE_SCHEME_COVERCRYPT)
                public, master = abe.covercrypt_add_dimension_buffer(
                    master, '{"name":"E","attributes":["present"]}')
                public, master = abe.covercrypt_add_attribute_buffer(master, "E", "added")
                user_key = abe.genkey_buffer(master, "A::present && E::added",
                                             abe.CPABE_SCHEME_COVERCRYPT)
                ciphertext = abe.call_hybrid_cpabe_encryptBuffer_with_scheme(
                    public, b"payload", "A::present && E::added", abe.CPABE_SCHEME_COVERCRYPT)
                self.assertEqual(abe.call_hybrid_cpabe_decryptBuffer(user_key, ciphertext), b"payload")

                base = root / "file-authority"
                self.assertEqual(abe.call_setup_with_scheme(str(base),
                                  abe.CPABE_SCHEME_COVERCRYPT), 0)
                updated1 = str(root / "new-dimension")
                updated2 = str(root / "new-attribute")
                self.assertEqual(abe.covercrypt_add_dimension(
                    str(base) + "_msk.key", '{"name":"E","attributes":["present"]}', updated1), 0)
                self.assertEqual(abe.covercrypt_add_attribute(
                    updated1 + "_msk.key", "E", "added", updated2), 0)
                self.assertTrue(Path(updated2 + "_pk.key").is_file())
                self.assertTrue(Path(updated2 + "_msk.key").is_file())
        finally:
            for key, original in (
                ("HCPABE_COVERCRYPT_CONFIG", original_config),
                ("HCPABE_COVERCRYPT_MODE", original_mode),
            ):
                if original is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original

if __name__ == "__main__":
    unittest.main()
