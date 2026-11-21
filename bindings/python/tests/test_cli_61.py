"""Exercise the 6.1 CLI through its normal Python entry point."""
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

PYTHON_BINDING = Path(__file__).resolve().parents[1]
DEMO_CONFIG = PYTHON_BINDING.parents[1] / "scripts" / "covercrypt-demo.json"
ATTRIBUTES = "Department::IT && Level::ADMIN"


class Cli61Tests(unittest.TestCase):
    def run_cli(self, directory, *arguments, success=True):
        env = dict(os.environ, PYTHONPATH=str(PYTHON_BINDING),
                   HCPABE_COVERCRYPT_CONFIG=str(DEMO_CONFIG), HCPABE_COVERCRYPT_MODE="hybridized")
        result = subprocess.run([sys.executable, "-m", "pq_cp_abe", *arguments], cwd=directory,
                                env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_covercrypt_named_flags_and_legacy_setup(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "plain").write_bytes(b"python\x00\xff")
            self.assertIn("--master-key", self.run_cli(root, "--genkey", success=False).stderr)
            self.run_cli(root, "--setup", "--scheme", "covercrypt", "--file", "demo",
                         "--with-signing-keys", "--ml-dsa", "65")
            self.run_cli(root, "--genkey", "--scheme", "covercrypt", "--master-key", "demo_msk.key",
                         "--attributes", ATTRIBUTES, "--user-key", "user.key")
            self.run_cli(root, "--encrypt", "--scheme", "covercrypt", "--public-key", "demo_pk.key",
                         "--file", "plain", "--policy", ATTRIBUTES, "--ciphertext", "cipher", "--sign",
                         "--signing-key", "demo_ml-dsa_sk.key", "--aes-bits", "192", "--ml-dsa", "65")
            self.assertEqual((root / "cipher").read_bytes()[:4], bytes((3, 2, 24, 65)))
            self.run_cli(root, "--decrypt", "--verify", "--user-key", "user.key", "--ciphertext", "cipher",
                         "--verification-key", "demo_ml-dsa_pk.key", "--output", "recovered")
            self.assertEqual((root / "recovered").read_bytes(), (root / "plain").read_bytes())
            self.run_cli(root, "setup-pqc", "--scheme", "ac17", "legacy")
            self.assertTrue((root / "legacy_pqc_sk.key").is_file())
            self.run_cli(root, "add_attribute", "--scheme", "covercrypt",
                         "demo_msk.key", "Department", "Ops", "updated")
            self.assertTrue((root / "updated_pk.key").is_file())
            self.run_cli(root, "setup_buffer", "--scheme", "ac17",
                         "--with-signing-keys", "--ml-dsa", "44")
