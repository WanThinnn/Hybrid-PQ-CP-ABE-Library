"""Use local fixture repositories; no network or real vendor files are changed."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('vendor_manager', ROOT / 'scripts/vendor.py')
VENDOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VENDOR)


class VendorGitTests(unittest.TestCase):
    def git(self, root, *args):
        return VENDOR.VendorGit.run(['git', *args], root).stdout.strip()

    def repository(self, path):
        path.mkdir()
        self.git(path, 'init', '-q')
        self.git(path, 'config', 'user.name', 'Fixture')
        self.git(path, 'config', 'user.email', 'fixture@localhost')
        self.git(path, 'config', 'commit.gpgsign', 'false')

    def test_init_and_pull_preserve_local_patches_and_parent_tracking(self):
        with tempfile.TemporaryDirectory(prefix='vendor fixture ') as directory:
            directory = Path(directory)
            upstream, root = directory / 'upstream', directory / 'project'
            self.repository(upstream)
            (upstream / '.gitignore').write_text('Cargo.lock\ntarget/\n')
            (upstream / 'library.c').write_text('upstream library\n')
            self.git(upstream, 'add', '.')
            self.git(upstream, 'commit', '-qm', 'base')
            base = self.git(upstream, 'rev-parse', 'HEAD')
            self.repository(root)
            work = root / 'vendor/example'
            work.mkdir(parents=True)
            (work / '.gitignore').write_text('Cargo.lock\ntarget/\n')
            (work / 'library.c').write_text('upstream library\nlocal integration patch\n')
            (work / 'Cargo.lock').write_text('pinned dependencies\n')
            (work / 'UPSTREAM.md').write_text(f'- Vendored commit: `{base}`\n')
            manifest = {'example': {'url': upstream.as_uri(), 'commit': base}}
            (root / 'vendor/upstreams.json').write_text(json.dumps(manifest))
            self.git(root, 'add', '.')
            self.git(root, 'add', '-f', 'vendor/example/Cargo.lock')
            self.git(root, 'commit', '-qm', 'vendored snapshot')
            files = {p.name: p.read_bytes() for p in work.iterdir()}
            manager = VENDOR.VendorGit(root)
            manager.init('example')
            self.assertEqual(files, {p.name: p.read_bytes() for p in work.iterdir()})
            self.assertFalse((work / '.git').exists())
            self.assertEqual(self.git(root, 'status', '--porcelain'), '')
            self.assertIn('Cargo.lock', manager.git('example', 'ls-files').stdout)
            manager.init('example')  # idempotent
            self.git(upstream, 'checkout', '-qb', 'upstream-next')
            (upstream / 'new-api.h').write_text('new upstream API\n')
            self.git(upstream, 'add', '.')
            self.git(upstream, 'commit', '-qm', 'upstream update')
            revision = self.git(upstream, 'rev-parse', 'HEAD')
            manager.pull('example')
            self.assertIn('local integration patch', (work / 'library.c').read_text())
            self.assertTrue((work / 'new-api.h').is_file())
            self.assertIn('vendor/example/new-api.h', self.git(root, 'ls-files', '--others', '--exclude-standard'))
            self.assertEqual(manager.git('example', 'status', '--porcelain').stdout, '')
            self.assertEqual(json.loads(manager.manifest.read_text())['example']['commit'], revision)

    def test_dirty_vendor_blocks_update_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            upstream, root = directory / 'upstream', directory / 'project'
            self.repository(upstream)
            (upstream / 'file').write_text('base\n')
            self.git(upstream, 'add', '.')
            self.git(upstream, 'commit', '-qm', 'base')
            base = self.git(upstream, 'rev-parse', 'HEAD')
            self.repository(root)
            work = root / 'vendor/example'
            work.mkdir(parents=True)
            (work / 'file').write_text('base\n')
            (root / 'vendor/upstreams.json').write_text(json.dumps({'example': {'url': upstream.as_uri(), 'commit': base}}))
            self.git(root, 'add', '.')
            self.git(root, 'commit', '-qm', 'snapshot')
            manager = VENDOR.VendorGit(root)
            manager.init('example')
            (work / 'file').write_text('uncommitted patch\n')
            with self.assertRaisesRegex(RuntimeError, 'snapshot local changes'):
                manager.update('example', 'not-a-real-ref')
            with self.assertRaisesRegex(RuntimeError, 'snapshot local changes'):
                manager.pull('example')
            self.assertEqual((work / 'file').read_text(), 'uncommitted patch\n')


if __name__ == '__main__':
    unittest.main()
