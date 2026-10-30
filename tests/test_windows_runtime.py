"""Check that Windows consumers do not need the private build directory."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(platform.system() == "Windows", "Windows runtime layout")
class WindowsRuntimeTests(unittest.TestCase):
    def test_runtime_is_published_for_library_and_cli_consumers(self):
        for relative in (
            "lib/libhybrid-pq-cp-abe.dll", "lib/libcpabe_tkn20.dll",
            "build/artifacts/windows/main.exe",
            "build/artifacts/windows/libcpabe_tkn20.dll",
        ):
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), f"Missing runtime output: {relative}")

    def test_public_dll_loads_with_only_its_published_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name in ("libhybrid-pq-cp-abe.dll", "libcpabe_tkn20.dll"):
                shutil.copy2(ROOT / "lib" / name, output / name)
            worker = """
import ctypes, os, sys
with os.add_dll_directory(os.getcwd()):
    library = ctypes.CDLL(os.path.abspath('libhybrid-pq-cp-abe.dll'), winmode=0x1100)
    library.getVersion.restype = ctypes.c_char_p
    assert library.getVersion()
    print(library.getVersion().decode())
"""
            result = subprocess.run([sys.executable, "-c", worker], cwd=output,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
