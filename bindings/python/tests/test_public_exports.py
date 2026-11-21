"""Exercise each native export through the packaged Python self-test."""
import sys
import re
from pathlib import Path
import unittest

PYTHON_ROOT = Path(__file__).resolve().parents[1]
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


class NativeExportsTests(unittest.TestCase):
    def test_every_public_c_function_has_a_ctypes_signature(self):
        from pq_cp_abe import native
        header = PYTHON_ROOT.parents[1] / "include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"
        names = re.findall(r"^\s*LIB_API\s+[^\n(]*?\b(\w+)\s*\(", header.read_text(encoding="utf-8"), re.M)
        self.assertGreater(len(names), 33)
        for name in names:
            with self.subTest(symbol=name):
                self.assertIsNotNone(getattr(native, name).argtypes)

    def test_all_33_exports_are_exercised(self):
        from pq_cp_abe.selftest import CompleteNativeSelfTest, EXPORTS
        self.assertEqual(len(EXPORTS), 33)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CompleteNativeSelfTest)
        result = unittest.TestResult()
        suite.run(result)
        if result.errors or result.failures:
            details = [
                f"{case}: {traceback}"
                for case, traceback in (result.errors + result.failures)
            ]
            self.fail("\n".join(details))
        self.assertEqual(result.testsRun, 1)


if __name__ == "__main__":
    unittest.main()
