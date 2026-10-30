"""Changing VERSION regenerates the public SDK header without a clean build."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAKE = shutil.which('make')


@unittest.skipUnless(MAKE, 'GNU Make required')
class VersionHeaderTests(unittest.TestCase):
    def test_version_changes_regenerate_the_header(self):
        with tempfile.TemporaryDirectory(prefix='version header ') as directory:
            root = Path(directory)
            shutil.copy2(ROOT / 'Makefile', root / 'Makefile')
            (root / 'scripts').mkdir()
            shutil.copy2(ROOT / 'scripts/windows-shell.sh', root / 'scripts/windows-shell.sh')
            header = root / 'include/hybrid_pq_cp_abe/version.h'
            header.parent.mkdir(parents=True)
            for version in ('6.0.0', '6.1.2-test'):
                (root / 'VERSION').write_text(version + '\n')
                if header.exists():
                    os.utime(header, (1, 1))
                result = subprocess.run([MAKE, 'include/hybrid_pq_cp_abe/version.h'], cwd=root,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f'#define HCPABE_LIB_VERSION "{version}"', header.read_text())


if __name__ == '__main__':
    unittest.main()
