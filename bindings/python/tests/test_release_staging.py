"""Offline regression tests for GitHub Release staging (never touch the network)."""

import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / "stage_native.py"
spec = importlib.util.spec_from_file_location("release_stager", SOURCE)
stager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stager)


def make_release(version="6.0.1", include_tkn20=True):
    archive_name = f"libhybrid-pq-cp-abe_win_x86_64_v{version}.zip"
    stem = archive_name[:-4]
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr(f"{stem}/lib/libhybrid-pq-cp-abe.dll", b"mock core")
        if include_tkn20:
            archive.writestr(f"{stem}/lib/libcpabe_tkn20.dll", b"mock tkn20")
    raw = data.getvalue()
    sums = f"{hashlib.sha256(raw).hexdigest()}  {archive_name}\n".encode()
    return archive_name, raw, sums


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        (base / "VERSION").write_text("6.0.1\n", encoding="utf-8")
        self.output = base / "pkg" / "_libs"
        self.patch_root = patch.object(stager, "ROOT", base)
        self.patch_pkg = patch.object(stager, "PACKAGE", self.output)
        self.patch_system = patch.object(stager.platform, "system", return_value="Windows")
        self.patch_arch = patch.object(stager, "normalized_arch", return_value="x86_64")
        for item in (self.patch_root, self.patch_pkg, self.patch_system, self.patch_arch):
            item.start()
            self.addCleanup(item.stop)

    def test_signed_release_archive_stages_core_and_tkn20(self):
        name, raw, sums = make_release()
        with patch.object(stager, "download", side_effect=lambda url, _: sums if url.endswith("SHA256SUMS.txt") else raw):
            files = stager.stage("windows", "x86_64")
        self.assertEqual({file.name for file in files}, {"libhybrid-pq-cp-abe.dll", "libcpabe_tkn20.dll"})
        self.assertEqual((self.output / "libcpabe_tkn20.dll").read_bytes(), b"mock tkn20")

    def test_rejects_checksum_mismatch(self):
        name, raw, sums = make_release()
        bad = b"0" * 64 + b"  " + name.encode() + b"\n"
        with patch.object(stager, "download", side_effect=lambda url, _: bad if url.endswith("SHA256SUMS.txt") else raw):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                stager.stage("windows", "x86_64")
        self.assertFalse(self.output.exists())

    def test_rejects_missing_tkn20(self):
        _, raw, sums = make_release(include_tkn20=False)
        with patch.object(stager, "download", side_effect=lambda url, _: sums if url.endswith("SHA256SUMS.txt") else raw):
            with self.assertRaisesRegex(ValueError, "Missing runtime files"):
                stager.stage("windows", "x86_64")

    def test_rejects_different_architecture(self):
        with patch.object(stager, "normalized_arch", return_value="arm64"):
            with self.assertRaisesRegex(RuntimeError, "Runner mismatch"):
                stager.stage("windows", "x86_64")

    def test_rejects_unsafe_version(self):
        (stager.ROOT / "VERSION").write_text("../bad", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "VERSION"):
            stager.release_version()


if __name__ == "__main__":
    unittest.main()
