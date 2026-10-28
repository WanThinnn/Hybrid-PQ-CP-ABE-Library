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
        names = [f"build/{target}/{name}" for name in core]
        names += [f"build/deps/{target}/lib/{name}" for name in dependencies]
        names += [f"build/deps/{target}/include/{name}" for name in (
            "cryptopp/aes.h", "rabe/rabe.h", "liboqs/oqs/oqs.h", "tkn20/cpabe_tkn20.h", "covercrypt/covercrypt_ffi.h")]
        names += ["include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h", "LICENSE", "NOTICE", "README.md", "VERSION"]
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
            (root / "build/windows/libhybrid-pq-cp-abe_dll.lib").unlink()
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


if __name__ == "__main__":
    unittest.main()
