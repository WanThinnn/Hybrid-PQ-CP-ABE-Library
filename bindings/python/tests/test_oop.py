"""Object API integration: configuration isolation, primitives and compatibility."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pq_cp_abe as abe
from pq_cp_abe.api import functional, legacy

CONFIG = {"dimensions": [
    {"name": "role", "attributes": ["admin", "analyst"]},
    {"name": "department", "attributes": ["finance", "engineering"]},
]}


class ObjectApiTests(unittest.TestCase):
    def test_abstract_base_and_facade(self):
        with self.assertRaises(TypeError):
            abe.BaseCPABE()
        for scheme, kind in ((abe.Scheme.AC17, abe.AC17CPABE), (abe.Scheme.TKN20, abe.TKN20CPABE)):
            instance = abe.PqCpAbe(scheme=scheme)
            self.assertIsInstance(instance.backend, kind)
            self.assertEqual(instance.scheme, scheme)
            with self.assertRaises(AttributeError):
                instance.scheme = abe.Scheme.COVERCRYPT
            keys = instance.setup()
            user = instance.generate_secret_key(keys.master_secret_key, "admin it")
            for message in (b"", b"\0OOP\xff"):
                encrypted = instance.encrypt(keys.public_key, message, "admin and it")
                self.assertEqual(instance.decrypt(user, encrypted), message)
                self.assertEqual(functional.decrypt(user, encrypted), message)
            signed_keys = instance.setup_with_signing()
            user = instance.keygen(signed_keys.master_secret_key, "admin it")
            encrypted = instance.encrypt_and_sign(signed_keys.public_key, signed_keys.signing_key, b"signed", "admin and it")
            self.assertEqual(instance.decrypt_and_verify(user, signed_keys.verification_key, encrypted), b"signed")

    @unittest.skipUnless(hasattr(abe.native, "hybrid_cpabe_covercrypt_setupBuffer_from_json"), "Rebuild native runtime for explicit CoverCrypt configuration")
    def test_covercrypt_instance_configuration_and_modes(self):
        import copy
        for mode in abe.KemMode:
            config = copy.deepcopy(CONFIG)
            with patch.dict("os.environ", {"HCPABE_COVERCRYPT_CONFIG": "", "HCPABE_COVERCRYPT_MODE": "classic"}):
                instance = abe.PqCpAbe(config=config, mode=mode)
                config["dimensions"].clear()  # Constructor must snapshot, not retain this dictionary.
                keys = instance.setup_with_signing()
                user = instance.keygen(keys.master_secret_key, "role::admin department::finance")
                denied = instance.keygen(keys.master_secret_key, "role::admin department::engineering")
                cipher = instance.encrypt(keys.public_key, b"private", "role::admin && department::finance")
                self.assertEqual(instance.decrypt(user, cipher), b"private")
                with self.assertRaises(abe.AbeError):
                    instance.decrypt(denied, cipher)
                cipher = instance.encrypt_and_sign(keys.public_key, keys.signing_key, b"signed", "role::admin")
                self.assertEqual(instance.decrypt_and_verify(user, keys.verification_key, cipher), b"signed")
        with self.assertRaises(NotImplementedError):
            abe.CoverCryptABE(parameter_set=512)

    def test_aes_key_sizes_authentication_and_immutability(self):
        for bits in (128, 192, 256):
            cipher = abe.AesGcm(bits)
            key, nonce = cipher.generate_key(), cipher.generate_nonce()
            self.assertEqual(len(key) * 8, bits)
            self.assertEqual(len(nonce), 12)
            for plaintext in (b"", b"payload"):
                nonce = cipher.generate_nonce()
                encrypted = cipher.encrypt(key, nonce, plaintext, b"aad")
                self.assertEqual(cipher.decrypt(key, nonce, encrypted, b"aad"), plaintext)
                with self.assertRaises(abe.AbeError):
                    cipher.decrypt(key, nonce, encrypted, b"wrong")
            with self.assertRaises(ValueError):
                cipher.encrypt(b"short", nonce, b"x")
            with self.assertRaises(FrozenInstanceError):
                cipher.key_size_bits = 128

    def test_ml_dsa_all_parameters_and_mismatched_keys(self):
        for parameter in abe.MlDsaParameterSet:
            if parameter != abe.MlDsaParameterSet.ML_DSA_87 and not hasattr(abe.native, "ml_dsa_generate_keypair"):
                continue  # Older binaries support only the fixed 87 primitive.
            signer = abe.MlDsa(parameter)
            keys = signer.generate_keypair()
            signature = signer.sign(b"", keys.secret_key)
            self.assertTrue(signer.verify(b"", signature, keys.public_key))
            self.assertFalse(signer.verify(b"tampered", signature, keys.public_key))
            with self.assertRaises((abe.AbeError, ValueError)):
                signer.sign(b"message", keys.secret_key[:-1])
        # Fixed 87 functions keep interoperating with the new parameterized object.
        pk, sk = legacy.ml_dsa_87_generate_keypair()
        signature = abe.MlDsa().sign(b"legacy", sk)
        self.assertTrue(legacy.ml_dsa_87_verify(b"legacy", signature, pk))

    @unittest.skipUnless(hasattr(abe.native, "ml_kem_generate_keypair"), "Rebuild native runtime for standalone ML-KEM")
    def test_ml_kem_all_parameters_and_implicit_rejection(self):
        for parameter in abe.MlKemParameterSet:
            kem = abe.MlKem(parameter)
            keys = kem.generate_keypair()
            result = kem.encapsulate(keys.public_key)
            self.assertEqual(kem.decapsulate(keys.secret_key, result.ciphertext), result.shared_secret)
            corrupted = bytearray(result.ciphertext)
            corrupted[-1] ^= 1
            self.assertNotEqual(kem.decapsulate(keys.secret_key, bytes(corrupted)), result.shared_secret)
            with self.assertRaises(abe.AbeError):
                kem.decapsulate(keys.secret_key, result.ciphertext[:-1])


if __name__ == "__main__":
    unittest.main()
