"""Python-friendly wrappers for the native C export table.

All C-owned buffers are copied into Python bytes and released with freeBuffer
even if a native call fails. No caller receives a dangling native pointer.
"""
import ctypes
from ctypes import byref, c_size_t, c_ubyte
from ._native import abe_lib, c_ubyte_p, CPABE_SCHEME_COVERCRYPT

HCPABE_SUCCESS = 0
HCPABE_ERR_SIGNATURE_INVALID = -9
ML_DSA_87_PUBLIC_KEY_BYTES = 2592
ML_DSA_87_SECRET_KEY_BYTES = 4896

def _data(value):
    if not isinstance(value, bytes):
        raise TypeError("Expected bytes for native input")
    # Preserve NULL for zero-size inputs where the C ABI accepts it.
    return (c_ubyte * len(value)).from_buffer_copy(value) if value else None

def _str(value):
    if not isinstance(value, str):
        raise TypeError("Expected str")
    if "\x00" in value:
        raise ValueError("Embedded NUL is forbidden")
    return value.encode("utf-8")

def _optional_str(value):
    return None if value is None else _str(value)

def _release(outputs):
    try:
        return tuple(ctypes.string_at(ptr, length.value) if length.value else b""
                     for ptr, length in outputs)
    finally:
        for ptr, _ in outputs:
            if ptr:
                abe_lib.freeBuffer(ptr)

def _run_outputs(fn, *arguments, count=1):
    outputs = [(c_ubyte_p(), c_size_t()) for _ in range(count)]
    args = list(arguments)
    for ptr, size in outputs:
        args.extend((byref(ptr), byref(size)))
    # Native functions may place a scheme after output arguments: use _run_scheme_outputs instead.
    result = fn(*args)
    if result != HCPABE_SUCCESS:
        msg = abe_lib.getErrorMessage(result)
        raise RuntimeError(f"{fn.__name__} failed: {msg.decode(errors='replace') if msg else result} ({result})")
    data = _release(outputs)
    return data[0] if count == 1 else data

def _run_scheme_outputs(fn, scheme, *arguments, count):
    outputs = [(c_ubyte_p(), c_size_t()) for _ in range(count)]
    args = list(arguments)
    for ptr, size in outputs:
        args.extend((byref(ptr), byref(size)))
    result = fn(*args, scheme)
    if result != HCPABE_SUCCESS:
        msg = abe_lib.getErrorMessage(result)
        raise RuntimeError(f"{fn.__name__} failed: {msg.decode(errors='replace') if msg else result} ({result})")
    data = _release(outputs)
    return data

def setup_buffer(scheme=CPABE_SCHEME_COVERCRYPT):
    """Return (public_key, master_secret_key) as bytes."""
    return _run_scheme_outputs(abe_lib.hybrid_cpabe_setupBuffer_with_scheme,
                               scheme, count=2)

def setup_buffer_with_pqc(scheme=CPABE_SCHEME_COVERCRYPT):
    """Return ABE PK/MSK (native bytes), then ML-DSA PK/SK (Base64-encoded bytes)."""
    return _run_scheme_outputs(abe_lib.hybrid_cpabe_setupBuffer_with_pqc_scheme,
                               scheme, count=4)

def genkey_buffer(master_secret_key: bytes, attributes: str, scheme=CPABE_SCHEME_COVERCRYPT):
    """Generate a scheme-specific private key in memory."""
    (key,) = _run_scheme_outputs(
        abe_lib.hybrid_cpabe_genkeyBuffer_with_scheme, scheme,
        _data(master_secret_key), len(master_secret_key), _str(attributes), count=1)
    return key

def covercrypt_add_attribute(master_key_file: str, dimension: str,
                             attribute: str, out_prefix: str, after: str | None = None):
    """Write a new authority PK/MSK pair, leaving the input MSK untouched."""
    return abe_lib.hybrid_cpabe_covercrypt_add_attribute(
        _str(master_key_file), _str(dimension), _str(attribute),
        _optional_str(after), _str(out_prefix))

def covercrypt_add_dimension(master_key_file: str, dimension_json: str, out_prefix: str):
    """Write an updated authority from a JSON dimension definition."""
    return abe_lib.hybrid_cpabe_covercrypt_add_dimension(
        _str(master_key_file), _str(dimension_json), _str(out_prefix))

def covercrypt_add_attribute_buffer(master_secret_key: bytes, dimension: str,
                                    attribute: str, after: str | None = None):
    """Return (updated_public_key, updated_master_key). Both must be persisted."""
    return _run_outputs(
        abe_lib.hybrid_cpabe_covercrypt_add_attributeBuffer,
        _data(master_secret_key), len(master_secret_key),
        _str(dimension), _str(attribute), _optional_str(after), count=2)

def covercrypt_add_dimension_buffer(master_secret_key: bytes, dimension_json: str):
    """Return (updated_public_key, updated_master_key). Both must be persisted."""
    return _run_outputs(
        abe_lib.hybrid_cpabe_covercrypt_add_dimensionBuffer,
        _data(master_secret_key), len(master_secret_key), _str(dimension_json), count=2)

def ml_dsa_87_generate_keypair():
    """Return (public_key, secret_key) bytes."""
    return _run_outputs(abe_lib.ml_dsa_87_generate_keypair, count=2)

def ml_dsa_87_sign(message: bytes, secret_key: bytes):
    if len(secret_key) != ML_DSA_87_SECRET_KEY_BYTES:
        raise ValueError(f"ML-DSA-87 secret key must be {ML_DSA_87_SECRET_KEY_BYTES} bytes")
    return _run_outputs(abe_lib.ml_dsa_87_sign, _data(message), len(message), _data(secret_key))

def ml_dsa_87_verify(message: bytes, signature: bytes, public_key: bytes):
    if len(public_key) != ML_DSA_87_PUBLIC_KEY_BYTES:
        raise ValueError(f"ML-DSA-87 public key must be {ML_DSA_87_PUBLIC_KEY_BYTES} bytes")
    result = abe_lib.ml_dsa_87_verify(_data(message), len(message),
                                       _data(signature), len(signature), _data(public_key))
    if result == HCPABE_ERR_SIGNATURE_INVALID:
        return False
    if result != HCPABE_SUCCESS:
        raise RuntimeError(f"ML-DSA-87 verification error ({result})")
    return True

def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b""):
    if len(key) != 32 or len(iv) != 12:
        raise ValueError("Use a 32-byte AES-256 key and a 12-byte GCM nonce")
    return _run_outputs(abe_lib.aes_gcm_encrypt, _data(key), len(key),
                        _data(iv), len(iv), _data(plaintext), len(plaintext),
                        _data(aad), len(aad))

def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes = b""):
    if len(key) != 32 or len(iv) != 12:
        raise ValueError("Use a 32-byte AES-256 key and a 12-byte GCM nonce")
    return _run_outputs(abe_lib.aes_gcm_decrypt, _data(key), len(key),
                        _data(iv), len(iv), _data(ciphertext), len(ciphertext),
                        _data(aad), len(aad))

def get_version():
    return abe_lib.getVersion().decode("utf-8")

def get_error_message(error_code: int):
    msg = abe_lib.getErrorMessage(error_code)
    return msg.decode("utf-8") if msg else ""
