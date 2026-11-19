"""Network-free regression tests of release downloader and wheel staging."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

MODULE_PATH = Path(__file__).resolve().parents[1] / "stage_native.py"
spec = importlib.util.spec_from_file_location("stage_native_under_test", MODULE_PATH)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def mock_release(include_tkn20=True):
    version = "6.0.1"
    name = f"libhybrid-pq-cp-abe_win_x86_64_v{version}.zip"
    archive_root = name[:-4]
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as zipfile_out:
        zipfile_out.writestr(f"{archive_root}/lib/libhybrid-pq-cp-abe.dll", b"test native DLL")
        if include_tkn20:
            zipfile_out.writestr(f"{archive_root}/lib/libcpabe_tkn20.dll", b"test TKN20 DLL")
    data = payload.getvalue()
    sums = f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode()
    return name, data, sums


class ReleaseStagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="staging-tests-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / "VERSION").write_text("6.0.1\n", encoding="utf-8")
        self.target = root / "package" / "_libs"
        for attr, val in (("ROOT", root), ("PACKAGE", self.target)):
            p = patch.object(stage, attr, val)
            p.start()
            self.addCleanup(p.stop)
        for attr, val in (("system", "Windows"),):
            p = patch.object(stage.platform, attr, return_value=val)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(stage, "normalized_arch", return_value="x86_64")
        p.start()
        self.addCleanup(p.stop)

    def _downloads(self, payload, sums):
        return patch.object(
            stage, "download",
            side_effect=lambda url, _: sums if url.endswith("SHA256SUMS.txt") else payload,
        )

    def test_stages_both_windows_dlls(self):
        _, payload, sums = mock_release()
        with self._downloads(payload, sums):
            output = stage.stage("windows", "x86_64")
        self.assertEqual({f.name for f in output}, {
            "libhybrid-pq-cp-abe.dll", "libcpabe_tkn20.dll",
        })
        self.assertEqual((self.target / "libcpabe_tkn20.dll").read_bytes(), b"test TKN20 DLL")

    def test_checksum_mismatch_rejected(self):
        name, payload, _ = mock_release()
        invalid = f"{'0' * 64}  {name}\n".encode()
        with self._downloads(payload, invalid):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                stage.stage("windows", "x86_64")
        self.assertFalse(self.target.exists())

    def test_missing_tkn20_rejected(self):
        _, payload, sums = mock_release(include_tkn20=False)
        with self._downloads(payload, sums):
            with self.assertRaisesRegex(ValueError, "Missing runtime files"):
                stage.stage("windows", "x86_64")

    def test_wrong_architecture_rejected(self):
        with patch.object(stage, "normalized_arch", return_value="arm64"):
            with self.assertRaisesRegex(RuntimeError, "Runner mismatch"):
                stage.stage("windows", "x86_64")

    def test_invalid_version_rejected(self):
        (stage.ROOT / "VERSION").write_text("../invalid", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "VERSION"):
            stage.release_version()


if __name__ == "__main__":
    unittest.main()
