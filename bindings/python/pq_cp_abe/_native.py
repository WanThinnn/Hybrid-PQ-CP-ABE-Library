"""Native C ABI loader for the Hybrid-PQ-CP-ABE library."""
import ctypes
from ctypes import POINTER, c_char_p, c_ubyte, c_size_t
import os
import platform
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_SYSTEM = platform.system()
_LIBRARY_NAMES = {
    "Windows": "libhybrid-pq-cp-abe.dll",
    "Linux": "libhybrid-pq-cp-abe.so",
    "Darwin": "libhybrid-pq-cp-abe.dylib",
}
if _SYSTEM not in _LIBRARY_NAMES:
    raise OSError(f"Unsupported operating system: {_SYSTEM}")

_lib_name = _LIBRARY_NAMES[_SYSTEM]
_candidates = [_PACKAGE_DIR / "_libs" / _lib_name]

# Keep source-tree development working until platform wheels are produced.
_repo_root = _PACKAGE_DIR.parents[2]
if (_repo_root / "Makefile").is_file() and (_repo_root / "bindings" / "python").is_dir():
    _candidates.append(_repo_root / "lib" / _lib_name)

_lib_path = next((path for path in _candidates if path.is_file()), None)
if _lib_path is None:
    raise OSError(
        f"Native library {_lib_name!r} not found. Checked: "
        + ", ".join(str(path) for path in _candidates)
        + ". Build the native library locally or install a wheel containing the binaries."
    )

# Retain the handles for the process lifetime so dependent DLLs stay discoverable.
_dll_directories = []
if _SYSTEM == "Windows":
    # The core DLL imports the separate Go/TKN20 runtime DLL.
    _tkn20_path = _lib_path.parent / "libcpabe_tkn20.dll"
    if not _tkn20_path.is_file():
        raise OSError(
            "Missing Windows TKN20 runtime: " + str(_tkn20_path)
            + ". Ship libcpabe_tkn20.dll beside libhybrid-pq-cp-abe.dll."
        )
    if hasattr(os, "add_dll_directory"):
        _dll_directories.append(os.add_dll_directory(str(_lib_path.parent)))

abe_lib = ctypes.CDLL(str(_lib_path))

# Setup function prototypes
abe_lib.setup.argtypes = [c_char_p]
abe_lib.setup.restype = ctypes.c_int

abe_lib.generateSecretKey.argtypes = [c_char_p, c_char_p, c_char_p]
abe_lib.generateSecretKey.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encrypt.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
abe_lib.hybrid_cpabe_encrypt.restype = ctypes.c_int

abe_lib.hybrid_cpabe_decrypt.argtypes = [c_char_p, c_char_p, c_char_p]
abe_lib.hybrid_cpabe_decrypt.restype = ctypes.c_int

abe_lib.getVersion.argtypes = []
abe_lib.getVersion.restype = c_char_p

abe_lib.getErrorMessage.argtypes = [ctypes.c_int]
abe_lib.getErrorMessage.restype = c_char_p

# Ctypes types for buffers
c_ubyte_p = POINTER(c_ubyte)

abe_lib.hybrid_cpabe_encryptBuffer.argtypes = [
    c_ubyte_p, c_size_t, # publicKey, pkLen
    c_ubyte_p, c_size_t, # plaintext, ptLen
    c_char_p,            # policy
    POINTER(c_ubyte_p), POINTER(c_size_t) # ciphertext, ctLen
]
abe_lib.hybrid_cpabe_encryptBuffer.restype = ctypes.c_int

abe_lib.hybrid_cpabe_decryptBuffer.argtypes = [
    c_ubyte_p, c_size_t, # privateKey, skLen
    c_ubyte_p, c_size_t, # ciphertext, ctLen
    POINTER(c_ubyte_p), POINTER(c_size_t) # plaintext, ptLen
]
abe_lib.hybrid_cpabe_decryptBuffer.restype = ctypes.c_int

# PQC hybrid functions
abe_lib.hybrid_cpabe_setup_with_pqc.argtypes = [c_char_p]
abe_lib.hybrid_cpabe_setup_with_pqc.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encrypt_and_sign.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
abe_lib.hybrid_cpabe_encrypt_and_sign.restype = ctypes.c_int

abe_lib.hybrid_cpabe_decrypt_and_verify.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
abe_lib.hybrid_cpabe_decrypt_and_verify.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encryptBuffer_and_sign.argtypes = [
    c_ubyte_p, c_size_t, # publicKey, pkLen
    c_ubyte_p, c_size_t, # pqcPrivKey, pqcPrivLen
    c_ubyte_p, c_size_t, # plaintext, ptLen
    c_char_p,            # policy
    POINTER(c_ubyte_p), POINTER(c_size_t) # ciphertext, ctLen
]
abe_lib.hybrid_cpabe_encryptBuffer_and_sign.restype = ctypes.c_int

abe_lib.hybrid_cpabe_decryptBuffer_and_verify.argtypes = [
    c_ubyte_p, c_size_t, # privateKey, skLen
    c_ubyte_p, c_size_t, # pqcPubKey, pqcPubLen
    c_ubyte_p, c_size_t, # ciphertext, ctLen
    POINTER(c_ubyte_p), POINTER(c_size_t) # plaintext, ptLen
]
abe_lib.hybrid_cpabe_decryptBuffer_and_verify.restype = ctypes.c_int

abe_lib.freeBuffer.argtypes = [c_ubyte_p]
abe_lib.freeBuffer.restype = None

# Scheme enum
CPABE_SCHEME_AC17 = 0
CPABE_SCHEME_TKN20 = 1
CPABE_SCHEME_COVERCRYPT = 2

# --- WITH SCHEME BINDINGS ---
abe_lib.setup_with_scheme.argtypes = [c_char_p, ctypes.c_int]
abe_lib.setup_with_scheme.restype = ctypes.c_int

abe_lib.hybrid_cpabe_setup_with_pqc_scheme.argtypes = [c_char_p, ctypes.c_int]
abe_lib.hybrid_cpabe_setup_with_pqc_scheme.restype = ctypes.c_int

abe_lib.generateSecretKey_with_scheme.argtypes = [c_char_p, c_char_p, c_char_p, ctypes.c_int]
abe_lib.generateSecretKey_with_scheme.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encrypt_with_scheme.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, ctypes.c_int]
abe_lib.hybrid_cpabe_encrypt_with_scheme.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encryptBuffer_with_scheme.argtypes = [
    c_ubyte_p, c_size_t, # publicKey, pkLen
    c_ubyte_p, c_size_t, # plaintext, ptLen
    c_char_p,            # policy
    POINTER(c_ubyte_p), POINTER(c_size_t), # ciphertext, ctLen
    ctypes.c_int         # scheme
]
abe_lib.hybrid_cpabe_encryptBuffer_with_scheme.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encrypt_and_sign_with_scheme.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, ctypes.c_int]
abe_lib.hybrid_cpabe_encrypt_and_sign_with_scheme.restype = ctypes.c_int

abe_lib.hybrid_cpabe_encryptBuffer_and_sign_with_scheme.argtypes = [
    c_ubyte_p, c_size_t, # publicKey, pkLen
    c_ubyte_p, c_size_t, # pqcPrivKey, pqcPrivLen
    c_ubyte_p, c_size_t, # plaintext, ptLen
    c_char_p,            # policy
    POINTER(c_ubyte_p), POINTER(c_size_t), # ciphertext, ctLen
    ctypes.c_int         # scheme
]
abe_lib.hybrid_cpabe_encryptBuffer_and_sign_with_scheme.restype = ctypes.c_int

# Remaining public C API functions from hybrid-pq-cp-abe.h.
# Returned native buffers must be released with freeBuffer, never libc.free().
_out_buf = POINTER(c_ubyte_p)
_out_len = POINTER(c_size_t)

def _declare(name, argtypes):
    func = getattr(abe_lib, name)
    func.argtypes = argtypes
    func.restype = ctypes.c_int

_declare("hybrid_cpabe_setupBuffer_with_scheme",
         [_out_buf, _out_len, _out_buf, _out_len, ctypes.c_int])
_declare("hybrid_cpabe_setupBuffer_with_pqc_scheme",
         [_out_buf, _out_len, _out_buf, _out_len,
          _out_buf, _out_len, _out_buf, _out_len, ctypes.c_int])
_declare("hybrid_cpabe_genkeyBuffer_with_scheme",
         [c_ubyte_p, c_size_t, c_char_p, _out_buf, _out_len, ctypes.c_int])

_declare("hybrid_cpabe_covercrypt_add_attribute",
         [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p])
_declare("hybrid_cpabe_covercrypt_add_dimension", [c_char_p, c_char_p, c_char_p])
_declare("hybrid_cpabe_covercrypt_add_attributeBuffer",
         [c_ubyte_p, c_size_t, c_char_p, c_char_p, c_char_p,
          _out_buf, _out_len, _out_buf, _out_len])
_declare("hybrid_cpabe_covercrypt_add_dimensionBuffer",
         [c_ubyte_p, c_size_t, c_char_p, _out_buf, _out_len, _out_buf, _out_len])

_declare("ml_dsa_87_generate_keypair", [_out_buf, _out_len, _out_buf, _out_len])
_declare("ml_dsa_87_sign", [c_ubyte_p, c_size_t, c_ubyte_p, _out_buf, _out_len])
_declare("ml_dsa_87_verify", [c_ubyte_p, c_size_t, c_ubyte_p, c_size_t, c_ubyte_p])

_declare("aes_gcm_encrypt",
         [c_ubyte_p, c_size_t, c_ubyte_p, c_size_t,
          c_ubyte_p, c_size_t, c_ubyte_p, c_size_t, _out_buf, _out_len])
_declare("aes_gcm_decrypt",
         [c_ubyte_p, c_size_t, c_ubyte_p, c_size_t,
          c_ubyte_p, c_size_t, c_ubyte_p, c_size_t, _out_buf, _out_len])

# Additive primitives are optional so legacy releases can still be imported.
# Calling an unavailable modern operation gives a clear capability error.
def get_function(name):
    function = getattr(abe_lib, name, None)
    if function is None:
        raise NotImplementedError(f"Native library does not support {name}; rebuild or install a matching release")
    return function

_parameterized_exports = {
    "hybrid_cpabe_covercrypt_setupBuffer_from_json": [c_char_p, ctypes.c_int, _out_buf, _out_len, _out_buf, _out_len],
    "aes_gcm_generate_key": [ctypes.c_int, _out_buf, _out_len],
    "ml_dsa_get_sizes": [ctypes.c_int, _out_len, _out_len, _out_len],
    "ml_dsa_generate_keypair": [ctypes.c_int, _out_buf, _out_len, _out_buf, _out_len],
    "ml_dsa_sign": [ctypes.c_int, c_ubyte_p, c_size_t, c_ubyte_p, c_size_t, _out_buf, _out_len],
    "ml_dsa_verify": [ctypes.c_int, c_ubyte_p, c_size_t, c_ubyte_p, c_size_t, c_ubyte_p, c_size_t],
    "ml_kem_get_sizes": [ctypes.c_int, _out_len, _out_len, _out_len, _out_len],
    "ml_kem_generate_keypair": [ctypes.c_int, _out_buf, _out_len, _out_buf, _out_len],
    "ml_kem_encapsulate": [ctypes.c_int, c_ubyte_p, c_size_t, _out_buf, _out_len, _out_buf, _out_len],
    "ml_kem_decapsulate": [ctypes.c_int, c_ubyte_p, c_size_t, c_ubyte_p, c_size_t, _out_buf, _out_len],
}
for _name, _arguments in _parameterized_exports.items():
    if hasattr(abe_lib, _name):
        _declare(_name, _arguments)
