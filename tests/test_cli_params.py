"""Run against an explicitly supplied freshly built CLI, never a stale DLL."""
import os
from pathlib import Path
import shlex
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

    def test_help_overview_and_command_help(self):
        overview = self.run_cli("--help").stdout.decode()
        self.assertIn("Usage: pq-cp-abe <command>", overview)
        self.assertIn("CoverCrypt setup", overview)
        for action in ("--with-signing-keys", "--sign ", "--verify"):
            self.assertIn(action, overview)
        detail = self.run_cli("encrypt", "--help").stdout
        self.assertTrue(detail.startswith(b"Usage: pq-cp-abe --encrypt "))
        self.assertIn(b"[signing-key]", detail)
        self.assertIn(b"--file FILE --policy POLICY --ciphertext FILE", detail)
        self.assertEqual(detail, self.run_cli("help", "encrypt").stdout)
        self.assertEqual(detail, self.run_cli("--encrypt", "--help").stdout)
        self.run_cli("help", "unknown-command", ok=False)

    def test_missing_arguments_show_named_usage(self):
        cases = (
            ("setup", b"--file PATH-OR-PREFIX"),
            ("genkey", b"--master-key FILE --attributes ATTRIBUTES --user-key FILE"),
            ("encrypt", b"--public-key FILE --file FILE --policy POLICY --ciphertext FILE"),
            ("decrypt", b"--user-key FILE --ciphertext FILE --output FILE"),
        )
        for command, fields in cases:
            for spelling in (command, f"--{command}"):
                with self.subTest(command=spelling):
                    error = self.run_cli(spelling, ok=False).stderr
                    self.assertTrue(error.startswith(f"Usage: pq-cp-abe --{command} ".encode()),
                                    error)
                    self.assertIn(fields, error)
                    self.assertIn(f"or: pq-cp-abe {command} ".encode(), error)
        self.assertIn(b"--sign --signing-key FILE",
                      self.run_cli("--encrypt", "--sign", ok=False).stderr)
        self.assertIn(b"--verify --verification-key FILE",
                      self.run_cli("--decrypt", "--verify", ok=False).stderr)

    def test_covercrypt_help_example(self):
        self.env["HCPABE_COVERCRYPT_CONFIG"] = str(
            Path(__file__).resolve().parents[1] / "scripts" / "covercrypt-demo.json"
        )
        plaintext = (self.folder / "plain").read_bytes()
        (self.folder / "data.txt").write_bytes(plaintext)
        overview = self.run_cli("--help").stdout.decode()
        self.assertIn("CoverCrypt example", overview)
        commands = [shlex.split(line) for line in overview.splitlines()
                    if line.startswith("  pq-cp-abe ")]
        self.assertEqual([command[1].removeprefix("--") for command in commands],
                         ["setup", "genkey", "encrypt", "decrypt"])
        for command in commands:
            self.run_cli(*command[1:])
        self.assertEqual((self.folder / "recovered.txt").read_bytes(), plaintext)

    def test_named_arguments_with_ml_dsa_signatures(self):
        self.run_cli("--setup", "--output", "keys", "--with-signing-keys", "--ml-dsa", "65")
        self.assertFalse((self.folder / "keys_pqc_sk.key").exists())
        self.assertFalse((self.folder / "keys_pqc_pk.key").exists())
        self.run_cli("genkey", "--user-key", "user", "--attributes", "admin it",
                     "--master-key", "keys_msk.key")
        self.run_cli("--encrypt", "--sign", "--ciphertext", "ct", "--policy", "admin and it",
                     "--file", "plain", "--signing-key", "keys_ml-dsa_sk.key",
                     "--public-key", "keys_pk.key", "--aes-bits", "192", "--ml-dsa", "65")
        self.assertEqual((self.folder / "ct").read_bytes()[:4], bytes((3, 0, 24, 65)))
        self.run_cli("--decrypt", "--verify", "--output", "recovered", "--ciphertext", "ct",
                     "--user-key", "user", "--verification-key", "keys_ml-dsa_pk.key")
        self.assertEqual((self.folder / "recovered").read_bytes(),
                         (self.folder / "plain").read_bytes())
        self.run_cli("--encrypt", "--ciphertext", "unsigned", "--policy", "admin and it",
                     "--file", "plain", "--public-key", "keys_pk.key")
        self.run_cli("--decrypt", "--verify", "--output", "unverified", "--ciphertext", "unsigned",
                     "--user-key", "user", "--verification-key", "keys_ml-dsa_pk.key", ok=False)
        self.assertFalse((self.folder / "unverified").exists())

    def test_ml_dsa_key_names_in_output_directory(self):
        directory = self.folder / "keys"
        directory.mkdir()
        self.run_cli("--setup", "--with-signing-keys", "--file", str(directory))
        self.assertEqual({path.name for path in directory.iterdir()},
                         {"cpabe_pk.key", "cpabe_msk.key", "ml-dsa_sk.key", "ml-dsa_pk.key"})

    def test_signature_actions_for_buffer_commands(self):
        setup = self.run_cli("setup_buffer", "--with-signing-keys", "--ml-dsa", "44")
        for name, key in zip(("pk", "msk", "verify", "sign"), setup.stdout.splitlines()[1::2]):
            (self.folder / name).write_bytes(key)
        genkey = self.run_cli("genkey_buffer", "msk", "admin")
        (self.folder / "user").write_bytes(genkey.stdout.splitlines()[-1])
        self.run_cli("encrypt_buffer", "--sign", "--ml-dsa", "44", "pk", "sign",
                     "example", "admin", "ct")
        plaintext = self.run_cli("decrypt_buffer", "--verify", "user", "verify", "ct")
        self.assertIn(b"Decrypted Buffer: example", plaintext.stdout)

    def test_buffer_text_can_match_a_named_file_option(self):
        self.run_cli("setup", "keys")
        self.run_cli("genkey", "keys_msk.key", "admin", "user")
        self.run_cli("encrypt_buffer", "keys_pk.key", "--ciphertext", "admin", "ct")
        self.run_cli("decrypt", "user", "ct", "recovered")
        self.assertEqual((self.folder / "recovered").read_bytes(), b"--ciphertext")

    def test_invalid_named_arguments(self):
        cases = (
            (("--setup", "--file", "--pqc"), b"--file requires a value"),
            (("--setup", "--file", "keys", "--file", "other"), b"more than once"),
            (("--setup", "--file", "keys", "--output", "other"), b"specify only one"),
            (("--setup", "--file", "keys", "--ciphertext", "ct"), b"Unknown argument for setup"),
            (("--setup", "--file", "keys", "other"), b"Use named arguments on their own"),
            (("--decrypt", "--ciphertext", "ct"), b"decrypt requires --user-key"),
            (("--decrypt", "--user-key", "user", "--ciphertext", "ct", "--output", "recovered",
              "--verification-key", "keys_pqc_pk.key"), b"--verification-key requires --verify"),
            (("--encrypt", "--public-key", "pk", "--file", "plain", "--policy", "admin",
              "--ciphertext", "ct", "--signing-key", "sign"), b"--signing-key requires --sign"),
            (("--setup", "--sign", "--file", "keys"), b"--sign is not valid for setup"),
            (("--encrypt", "--verify"), b"--verify is not valid for encrypt"),
            (("--decrypt", "--with-signing-keys"), b"--with-signing-keys is not valid for decrypt"),
            (("--genkey", "--sign"), b"--sign is not valid for genkey"),
            (("--setup", "--ml-dsa", "87", "--file", "keys"), b"--ml-dsa requires --with-signing-keys"),
            (("--decrypt", "--verify", "--ml-dsa", "87"), b"--ml-dsa requires --with-signing-keys"),
        )
        for args, message in cases:
            with self.subTest(args=args):
                error = self.run_cli(*args, ok=False).stderr
                self.assertIn(message, error)
                self.assertIn(f"Usage: pq-cp-abe {args[0]} ".encode(), error)
        self.assertFalse((self.folder / "keys_pk.key").exists())

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
