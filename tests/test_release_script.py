"""Exercise release preflight in local fixture repos; never publish a release."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'Run shell preflight regressions on Linux')
class ReleaseScriptTests(unittest.TestCase):
    def fixture(self, directory, version='6.0.0'):
        root = Path(directory) / 'repo'
        (root / 'scripts').mkdir(parents=True)
        shutil.copy2(ROOT / 'scripts/release.sh', root / 'scripts/release.sh')
        (root / 'VERSION').write_text(version + '\n')
        (root / 'include/hybrid_pq_cp_abe').mkdir(parents=True)
        (root / 'include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h').write_text(
            '#include "version.h"\nconst char* const LIB_VERSION = HCPABE_LIB_VERSION;\n')
        # The generated, ignored version.h must not be a release prerequisite.
        (root / 'release_notes').mkdir()
        (root / 'release_notes/v6.0.0.md').write_text('# Release 6.0.0\n')
        self.git(root, 'init', '-q')
        self.git(root, 'add', '.')
        self.git(root, '-c', 'user.name=Release Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'Fixture')
        remote = Path(directory) / 'origin.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(remote)], check=True)
        self.git(root, 'remote', 'add', 'origin', str(remote))
        return root

    def git(self, root, *args):
        return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, text=True)

    def call(self, root, *args):
        return subprocess.run(['bash', str(root / 'scripts/release.sh'), *args],
                              input='n\n', capture_output=True, text=True, timeout=20)

    def test_macro_version_passes_without_generated_header_and_cancels_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            result = self.call(root, '6.0.0')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('Release cancelled.', result.stdout)
            self.assertIn('vault-plugin-abe_linux_x86_64_v6.0.0.zip', result.stdout)
            self.assertEqual(self.git(root, 'tag', '--list').stdout, '')
            self.assertEqual(self.git(root, 'status', '--porcelain').stdout, '')

    def test_wrong_root_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory, version='5.2.1')
            result = self.call(root, '6.0.0')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Update and commit VERSION to 6.0.0', result.stderr)
            self.assertEqual(self.git(root, 'tag', '--list').stdout, '')

    def test_dirty_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / 'VERSION').write_text('6.0.1\n')
            result = self.call(root, '6.0.0')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Commit or stash', result.stderr)

    def test_existing_tag_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            self.git(root, 'tag', 'v6.0.0')
            before = self.git(root, 'rev-parse', 'refs/tags/v6.0.0').stdout
            result = self.call(root, '6.0.0')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('already exists; refusing to replace it', result.stderr)
            self.assertEqual(self.git(root, 'rev-parse', 'refs/tags/v6.0.0').stdout, before)


if __name__ == '__main__':
    unittest.main()
