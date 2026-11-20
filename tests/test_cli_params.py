"""Run against an explicitly supplied freshly built CLI, never a stale DLL."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

EXEC = os.environ.get("HCPABE_PARAMS_EXEC")
if __name__ == "__main__" and len(sys.argv) > 1:
    EXEC = sys.argv.pop(1)
if EXEC:
    EXEC = str(Path(EXEC).resolve())


@unittest.skipUnless(EXEC, "Supply the built CLI path or HCPABE_PARAMS_EXEC")
class CliParameterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hcpabe-cli-params-")
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.env = os.environ.copy()
        config = self.folder / "config.json"
        config.write_text('{"dimensions":[{"name":"admin","attributes":["present","absent"]},'
                          '{"name":"it","attributes":["present","absent"]}]}', encoding="utf-8")
        self.env["HCPABE_COVERCRYPT_CONFIG"] = str(config)
        self.env["HCPABE_COVERCRYPT_MODE"] = "hybridized"
        (self.folder / "plain").write_bytes(b"CLI\0binary\xff")

    def run_cli(self, *args, ok=True):
        result = subprocess.run([EXEC, *args], cwd=self.folder, env=self.env, capture_output=True, timeout=60)
        self.assertEqual(result.returncode == 0, ok, (args, result.stdout, result.stderr))
        return result

    def test_parameter_matrix_and_legacy_defaults(self):
        for scheme_id, scheme in enumerate(("ac17", "tkn20", "covercrypt")):
            for parameter in (44, 65, 87):
                with self.subTest(scheme=scheme, ml_dsa=parameter):
                    self.run_cli("setup", "--scheme", scheme, "--pqc", "--ml-dsa", str(parameter), "keys")
                    self.run_cli("genkey", "--scheme", scheme, "keys_msk.key", "admin it", "user")
                    for bits in (128, 192, 256):
                        self.run_cli("encrypt", "--scheme", scheme, "--pqc", "--aes-bits", str(bits),
                                     "--ml-dsa", str(parameter), "keys_pk.key", "keys_pqc_sk.key", "plain", "admin and it", "ct")
                        self.assertEqual((self.folder / "ct").read_bytes()[:4], bytes((3, scheme_id, bits // 8, parameter)))
                        self.run_cli("decrypt", "--pqc", "user", "keys_pqc_pk.key", "ct", "recovered")
                        self.assertEqual((self.folder / "recovered").read_bytes(), (self.folder / "plain").read_bytes())
                        self.run_cli("encrypt_buffer", "--scheme", scheme, "--aes-bits", str(bits),
                                     "keys_pk.key", "hello", "admin and it", "ct")
                        self.assertEqual((self.folder / "ct").read_bytes()[:4], bytes((3, scheme_id, bits // 8, 0)))
                        self.run_cli("decrypt", "user", "ct", "recovered")
                        self.assertEqual((self.folder / "recovered").read_bytes(), b"hello")
            self.run_cli("setup", "--scheme", scheme, "--pqc", "legacy")
            self.run_cli("genkey", "--scheme", scheme, "legacy_msk.key", "admin it", "legacy_user")
            for flags in ([], ["--pqc"]):
                keys = ["legacy_pk.key", "legacy_pqc_sk.key"] if flags else ["legacy_pk.key"]
                self.run_cli("encrypt", "--scheme", scheme, *flags, *keys, "plain", "admin and it", "ct")
                self.assertEqual((self.folder / "ct").read_bytes()[0], 2)
                verify = ["legacy_pqc_pk.key"] if flags else []
                self.run_cli("decrypt", *flags, "legacy_user", *verify, "ct", "recovered")
                self.assertEqual((self.folder / "recovered").read_bytes(), (self.folder / "plain").read_bytes())

    def test_invalid_flags_and_missing_values(self):
        for args in (("encrypt", "--aes-bits"), ("encrypt", "--aes-bits", "129"),
                     ("encrypt", "--ml-dsa", "65"), ("setup", "--pqc", "--ml-dsa", "45", "keys"),
                     ("decrypt", "--aes-bits", "128"), ("setup", "--aes-bits", "256", "keys"),
                     ("decrypt", "--pqc", "--ml-dsa", "87")):
            with self.subTest(args=args):
                self.run_cli(*args, ok=False)
        self.assertFalse((self.folder / "keys_pk.key").exists())


if __name__ == "__main__":
    unittest.main()
