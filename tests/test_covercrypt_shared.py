"""Exercise the standalone CoverCrypt shared library through its public C ABI."""
import ctypes as c
from pathlib import Path
import platform
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Buffer(c.Structure):
    _fields_ = [("data", c.POINTER(c.c_uint8)), ("len", c.c_size_t)]

    def read(self):
        return c.string_at(self.data, self.len)


class SharedCovercryptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        system = platform.system()
        folder, filename = {
            "Windows": ("windows", "covercrypt_ffi.dll"),
            "Linux": ("linux", "libcovercrypt_ffi.so"),
            "Darwin": ("macos", "libcovercrypt_ffi.dylib"),
        }[system]
        path = ROOT / "build/deps" / folder / "lib/covercrypt" / filename
        if not path.is_file():
            raise unittest.SkipTest("Build the dependencies with make deps -j8")
        cls.lib = c.CDLL(str(path))
        out = c.POINTER(Buffer)
        signatures = {
            "cc_setup": [c.c_char_p, c.c_int, out, out],
            "cc_genkey": [c.c_void_p, c.c_size_t, c.c_char_p, out, out],
            "cc_genkey_ephemeral": [c.c_void_p, c.c_size_t, c.c_char_p, out],
            "cc_encaps": [c.c_void_p, c.c_size_t, c.c_char_p, out, out],
            "cc_decaps": [c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, out],
        }
        for name, arguments in signatures.items():
            function = getattr(cls.lib, name)
            function.argtypes, function.restype = arguments, c.c_int
        cls.lib.cc_buffer_free.argtypes = [out]
        cls.lib.cc_buffer_free.restype = None

    def test_persisted_and_ephemeral_users_have_the_same_access(self):
        config = b'{"dimensions":[{"name":"D","attributes":["yes","no"]}]}'
        for mode in (0, 1, 2):
            with self.subTest(mode=mode):
                buffers = [Buffer() for _ in range(10)]
                msk, mpk, updated, persisted, ephemeral, denied, secret, enc, first, second = buffers
                try:
                    self.assertEqual(self.lib.cc_setup(config, mode, c.byref(msk), c.byref(mpk)), 0)
                    original = msk.read()
                    self.assertEqual(self.lib.cc_genkey(msk.data, msk.len, b'D::yes',
                                                       c.byref(updated), c.byref(persisted)), 0)
                    self.assertEqual(self.lib.cc_genkey_ephemeral(msk.data, msk.len, b'D::yes',
                                                                 c.byref(ephemeral)), 0)
                    self.assertEqual(self.lib.cc_genkey_ephemeral(msk.data, msk.len, b'D::no',
                                                                 c.byref(denied)), 0)
                    self.assertEqual(msk.read(), original)
                    self.assertEqual(self.lib.cc_encaps(mpk.data, mpk.len, b'D::yes',
                                                       c.byref(secret), c.byref(enc)), 0)
                    for user, output in ((persisted, first), (ephemeral, second)):
                        self.assertEqual(self.lib.cc_decaps(user.data, user.len, enc.data, enc.len,
                                                           c.byref(output)), 0)
                        self.assertEqual(output.read(), secret.read())
                    self.lib.cc_buffer_free(c.byref(first))
                    self.assertEqual(self.lib.cc_decaps(denied.data, denied.len, enc.data, enc.len,
                                                       c.byref(first)), -3)
                    self.assertFalse(first.data)
                    self.assertEqual(self.lib.cc_genkey_ephemeral(msk.data, msk.len, b'D::yes', None), -1)
                finally:
                    for buffer in buffers:
                        self.lib.cc_buffer_free(c.byref(buffer))


if __name__ == "__main__":
    unittest.main()
