import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/package-release.py"
SPEC = importlib.util.spec_from_file_location("package_release", SCRIPT)
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class ReleasePackageTests(unittest.TestCase):
    def fixture(self, root, target):
        core, dependencies = PACKAGE.required_outputs(target)
        names = [f"build/artifacts/{target}/{name}" for name in core]
        names += [f"build/deps/{target}/lib/{name}" for name in dependencies]
        names += [f"build/deps/{target}/include/{name}" for name in (
            "cryptopp/aes.h", "rabe/rabe.h", "liboqs/oqs/oqs.h", "tkn20/cpabe_tkn20.h", "covercrypt/covercrypt_ffi.h")]
        names += ["include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h", "include/hybrid_pq_cp_abe/version.h",
                  "LICENSE", "NOTICE", "README.md", "VERSION"]
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture-build-output")

    def test_all_platform_layouts_include_headers_libraries_and_cli(self):
        for target, arch in PACKAGE.TARGETS:
            with self.subTest(target=target, arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, target)
                package = root / "package"
                PACKAGE.stage_package(root, package, target)
                core, dependencies = PACKAGE.required_outputs(target)
                for name in core:
                    folder = "bin" if name in {"main", "main.exe"} else "lib"
                    self.assertTrue((package / folder / name).is_file())
                for name in dependencies:
                    self.assertTrue((package / "lib/deps" / name).is_file())
                self.assertTrue((package / "include/liboqs/oqs/oqs.h").is_file())
                if target == "windows":
                    self.assertTrue((package / "bin/libcpabe_tkn20.dll").is_file())
                    self.assertTrue((package / "lib/libcpabe_tkn20.dll").is_file())

    def test_missing_dll_import_library_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "windows")
            (root / "build/artifacts/windows/libhybrid-pq-cp-abe_dll.lib").unlink()
            with self.assertRaises(FileNotFoundError):
                PACKAGE.stage_package(root, root / "package", "windows")

    def test_lfs_pointer_is_not_a_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "library.a"
            path.write_text("version https://git-lfs.github.com/spec/v1\noid sha256:123\n")
            with self.assertRaises(ValueError):
                PACKAGE.require_file(path)

    def test_epoch_dated_dependency_license_can_be_zipped(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "package"
            package.mkdir()
            license = package / "LICENSE"
            license.write_bytes(b"original license text")
            os.utime(license, (0, 0))
            archive = Path(directory) / "package.zip"
            PACKAGE.write_archive(package, archive)
            with zipfile.ZipFile(archive) as zipped:
                self.assertEqual(zipped.read("package/LICENSE"), b"original license text")
                self.assertEqual(zipped.getinfo("package/LICENSE").date_time[0], 1980)

    def test_unsafe_versions_are_rejected(self):
        for version in ("", "../escape", "a/b", "v", "a;command", "a\ncommand"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                PACKAGE.version_string(version)
        self.assertEqual(PACKAGE.version_string("v5.2.0-rc1"), "5.2.0-rc1")

    def test_publish_requires_exactly_all_platform_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            command = [sys.executable, str(SCRIPT), "--verify-assets", str(output), "--version", "v5.2.0"]
            result = subprocess.run(command, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            for target, arch in PACKAGE.TARGETS:
                (output / (PACKAGE.archive_name(target, arch, "5.2.0") + ".zip")).touch()
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            (output / "unexpected.zip").touch()
            result = subprocess.run(command, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


    def test_vault_package_requires_the_shared_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = ["build/artifacts/linux/vault/vault-plugin-abe", "LICENSE", "NOTICE", "VERSION",
                      "plugins/vault/README.md", "plugins/vault/TESTING.md", "scripts/covercrypt-demo.json"]
            for name in inputs:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture-package-input")
            with self.assertRaises(FileNotFoundError):
                PACKAGE.stage_vault_package(root, root / "package")
            library = root / "build/artifacts/linux/vault/libhybrid-pq-cp-abe.so"
            library.write_bytes(b"fixture-library")
            package = root / "package"
            PACKAGE.stage_vault_package(root, package)
            for name in ("vault-plugin-abe", library.name, "config/covercrypt-demo.json", "PACKAGE.md"):
                self.assertTrue((package / name).is_file(), name)

    def test_publish_requires_linux_named_vault_asset_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            command = [sys.executable, str(SCRIPT), "--verify-assets", str(output),
                       "--include-vault", "--version", "v6.0.0"]
            for target, arch in PACKAGE.TARGETS:
                (output / (PACKAGE.archive_name(target, arch, "6.0.0") + ".zip")).touch()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            name = PACKAGE.vault_archive_name("x86_64", "6.0.0") + ".zip"
            self.assertEqual(name, "vault-plugin-abe_linux_x86_64_v6.0.0.zip")
            asset = output / name
            asset.touch()
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            asset.rename(output / name.replace("_linux_", "_windows_"))
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
