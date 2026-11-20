"""Compatibility API: preserves call_* and historical helper behavior.

Only this module implements legacy wrappers. New applications use functional.
"""
"""Python callable wrappers around the native C ABI (existing API preserved)."""
import ctypes
from ctypes import c_ubyte, c_size_t, byref

from .._native import (
    abe_lib, c_ubyte_p,
    CPABE_SCHEME_AC17, CPABE_SCHEME_TKN20, CPABE_SCHEME_COVERCRYPT,
)

# Error codes
HCPABE_SUCCESS = 0
HCPABE_ERR_FILE_NOT_FOUND = -1
HCPABE_ERR_INVALID_KEY = -2
HCPABE_ERR_POLICY_MISMATCH = -3
HCPABE_ERR_CRYPTO_FAILED = -4
HCPABE_ERR_INVALID_PARAM = -5
HCPABE_ERR_MEMORY = -6
HCPABE_ERR_UNSUPPORTED_FORMAT = -7
HCPABE_ERR_VERSION_MISMATCH = -8
HCPABE_ERR_SIGNATURE_INVALID = -9

def _call_scheme(legacy, scheme_aware, scheme, *arguments):
    if scheme == CPABE_SCHEME_AC17:
        return legacy(*arguments)
    return scheme_aware(*arguments, scheme)


# Python functions wrapping C++ library functions
def call_setup(path_to_save_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = _call_scheme(abe_lib.setup, abe_lib.setup_with_scheme, scheme,
        path_to_save_file.encode('utf-8'),
    )
    if result == HCPABE_SUCCESS:
        print(f"Setup completed successfully!")
        print(f"   Files created in: {path_to_save_file}/")
        print(f"   - cpabe_msk.key (Master Secret Key)")
        print(f"   - cpabe_pk.key  (Public Parameters)")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Setup failed: {error_msg} (code: {result})")
    return result

def call_generate_secret_key(master_key_file, attributes, private_key_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = _call_scheme(abe_lib.generateSecretKey, abe_lib.generateSecretKey_with_scheme, scheme,
        master_key_file.encode('utf-8'),
        attributes.encode('utf-8'),
        private_key_file.encode('utf-8'),
    )
    if result == HCPABE_SUCCESS:
        print(f"Secret key generated successfully!")
        print(f"   Attributes: {attributes}")
        print(f"   Output: {private_key_file}")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Key generation failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encrypt(public_key_file, plaintext_file, policy, ciphertext_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = _call_scheme(abe_lib.hybrid_cpabe_encrypt, abe_lib.hybrid_cpabe_encrypt_with_scheme, scheme,
        public_key_file.encode('utf-8'),
        plaintext_file.encode('utf-8'),
        policy.encode('utf-8'),
        ciphertext_file.encode('utf-8'),
    )
    if result == HCPABE_SUCCESS:
        print(f"Encryption successful!")
        print(f"   Policy: {policy}")
        print(f"   Output: {ciphertext_file}")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Encryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_decrypt(private_key_file, ciphertext_file, recovertext_file):
    result = abe_lib.hybrid_cpabe_decrypt(private_key_file.encode('utf-8'),
                                   ciphertext_file.encode('utf-8'),
                                   recovertext_file.encode('utf-8'))
    if result == HCPABE_SUCCESS:
        print(f"Decryption successful!")
        print(f"   Output: {recovertext_file}")
    elif result == HCPABE_ERR_POLICY_MISMATCH:
        print(f"Decryption failed: Attributes do not satisfy policy")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Decryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encryptBuffer(public_key: bytes, plaintext: bytes, policy: str, scheme: int = CPABE_SCHEME_COVERCRYPT) -> bytes:
    if scheme != CPABE_SCHEME_AC17:
        return call_hybrid_cpabe_encryptBuffer_with_scheme(public_key, plaintext, policy, scheme)
    pk_arr = (c_ubyte * len(public_key)).from_buffer_copy(public_key)
    pt_arr = (c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    
    ct_ptr = c_ubyte_p()
    ct_len = c_size_t(0)
    
    result = abe_lib.hybrid_cpabe_encryptBuffer(
        pk_arr, len(public_key),
        pt_arr, len(plaintext),
        policy.encode('utf-8'),
        byref(ct_ptr), byref(ct_len)
    )
    
    if result == HCPABE_SUCCESS:
        ct_bytes = bytes(ct_ptr[:ct_len.value])
        abe_lib.freeBuffer(ct_ptr)
        return ct_bytes
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        raise RuntimeError(f"Buffer encryption failed: {error_msg} (code: {result})")

def call_hybrid_cpabe_decryptBuffer(private_key: bytes, ciphertext: bytes) -> bytes:
    sk_arr = (c_ubyte * len(private_key)).from_buffer_copy(private_key)
    ct_arr = (c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
    
    pt_ptr = c_ubyte_p()
    pt_len = c_size_t(0)
    
    result = abe_lib.hybrid_cpabe_decryptBuffer(
        sk_arr, len(private_key),
        ct_arr, len(ciphertext),
        byref(pt_ptr), byref(pt_len)
    )
    
    if result == HCPABE_SUCCESS:
        pt_bytes = bytes(pt_ptr[:pt_len.value])
        abe_lib.freeBuffer(pt_ptr)
        return pt_bytes
    elif result == HCPABE_ERR_POLICY_MISMATCH:
        raise RuntimeError(f"Buffer decryption failed: Attributes do not satisfy policy")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        raise RuntimeError(f"Buffer decryption failed: {error_msg} (code: {result})")

# Python wrappers for PQC functions
def call_hybrid_cpabe_setup_with_pqc(path_to_save_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = _call_scheme(abe_lib.hybrid_cpabe_setup_with_pqc, abe_lib.hybrid_cpabe_setup_with_pqc_scheme, scheme,
        path_to_save_file.encode('utf-8'),
    )
    if result == HCPABE_SUCCESS:
        print(f"Setup with PQC completed successfully!")
        print(f"   Files created in: {path_to_save_file}/")
        print(f"   - cpabe_msk.key (Master Secret Key)")
        print(f"   - cpabe_pk.key  (Public Parameters)")
        print(f"   - pqc_sk.key    (ML-DSA Secret Key)")
        print(f"   - pqc_pk.key    (ML-DSA Public Key)")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Setup failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encrypt_and_sign(public_key_file, pqc_private_key_file, plaintext_file, policy, ciphertext_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = _call_scheme(abe_lib.hybrid_cpabe_encrypt_and_sign, abe_lib.hybrid_cpabe_encrypt_and_sign_with_scheme, scheme,
        public_key_file.encode('utf-8'),
        pqc_private_key_file.encode('utf-8'),
        plaintext_file.encode('utf-8'),
        policy.encode('utf-8'),
        ciphertext_file.encode('utf-8'),
    )
    if result == HCPABE_SUCCESS:
        print(f"Encryption & Sign successful!")
        print(f"   Policy: {policy}")
        print(f"   Output: {ciphertext_file}")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Encryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_decrypt_and_verify(private_key_file, pqc_public_key_file, ciphertext_file, recovertext_file):
    result = abe_lib.hybrid_cpabe_decrypt_and_verify(
        private_key_file.encode('utf-8'),
        pqc_public_key_file.encode('utf-8'),
        ciphertext_file.encode('utf-8'),
        recovertext_file.encode('utf-8')
    )
    if result == HCPABE_SUCCESS:
        print(f"Decryption & Verify successful!")
        print(f"   Output: {recovertext_file}")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Decryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encryptBuffer_and_sign(public_key: bytes, pqc_priv_key: bytes, plaintext: bytes, policy: str, scheme: int = CPABE_SCHEME_COVERCRYPT) -> bytes:
    if scheme != CPABE_SCHEME_AC17:
        return call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme(public_key, pqc_priv_key, plaintext, policy, scheme)
    pk_arr = (c_ubyte * len(public_key)).from_buffer_copy(public_key)
    pqc_sk_arr = (c_ubyte * len(pqc_priv_key)).from_buffer_copy(pqc_priv_key)
    pt_arr = (c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    
    ct_ptr = c_ubyte_p()
    ct_len = c_size_t(0)
    
    result = abe_lib.hybrid_cpabe_encryptBuffer_and_sign(
        pk_arr, len(public_key),
        pqc_sk_arr, len(pqc_priv_key),
        pt_arr, len(plaintext),
        policy.encode('utf-8'),
        byref(ct_ptr), byref(ct_len)
    )
    
    if result == HCPABE_SUCCESS:
        ct_bytes = bytes(ct_ptr[:ct_len.value])
        abe_lib.freeBuffer(ct_ptr)
        return ct_bytes
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        raise RuntimeError(f"Buffer PQC encryption failed: {error_msg} (code: {result})")

def call_hybrid_cpabe_decryptBuffer_and_verify(private_key: bytes, pqc_pub_key: bytes, ciphertext: bytes) -> bytes:
    sk_arr = (c_ubyte * len(private_key)).from_buffer_copy(private_key)
    pqc_pk_arr = (c_ubyte * len(pqc_pub_key)).from_buffer_copy(pqc_pub_key)
    ct_arr = (c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
    
    pt_ptr = c_ubyte_p()
    pt_len = c_size_t(0)
    
    result = abe_lib.hybrid_cpabe_decryptBuffer_and_verify(
        sk_arr, len(private_key),
        pqc_pk_arr, len(pqc_pub_key),
        ct_arr, len(ciphertext),
        byref(pt_ptr), byref(pt_len)
    )
    
    if result == HCPABE_SUCCESS:
        pt_bytes = bytes(pt_ptr[:pt_len.value])
        abe_lib.freeBuffer(pt_ptr)
        return pt_bytes
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        raise RuntimeError(f"Buffer PQC decryption failed: {error_msg} (code: {result})")

# --- WRAPPERS WITH SCHEME ---
def call_setup_with_scheme(path_to_save_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = abe_lib.setup_with_scheme(path_to_save_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Setup failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_setup_with_pqc_scheme(path_to_save_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = abe_lib.hybrid_cpabe_setup_with_pqc_scheme(path_to_save_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"PQC Setup failed: {error_msg} (code: {result})")
    return result

def call_generate_secret_key_with_scheme(master_key_file, attributes, private_key_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = abe_lib.generateSecretKey_with_scheme(master_key_file.encode('utf-8'),
                                        attributes.encode('utf-8'),
                                        private_key_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Key generation failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encrypt_with_scheme(public_key_file, plaintext_file, policy, ciphertext_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = abe_lib.hybrid_cpabe_encrypt_with_scheme(public_key_file.encode('utf-8'),
                                   plaintext_file.encode('utf-8'),
                                   policy.encode('utf-8'),
                                   ciphertext_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Encryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encryptBuffer_with_scheme(public_key: bytes, plaintext: bytes, policy: str, scheme: int = CPABE_SCHEME_COVERCRYPT) -> bytes:
    pk_arr = (c_ubyte * len(public_key)).from_buffer_copy(public_key)
    pt_arr = (c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    ct_ptr = c_ubyte_p()
    ct_len = c_size_t(0)
    result = abe_lib.hybrid_cpabe_encryptBuffer_with_scheme(
        pk_arr, len(public_key), pt_arr, len(plaintext),
        policy.encode('utf-8'), byref(ct_ptr), byref(ct_len), scheme
    )
    if result == HCPABE_SUCCESS:
        ct_bytes = bytes(ct_ptr[:ct_len.value])
        abe_lib.freeBuffer(ct_ptr)
        return ct_bytes
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        raise RuntimeError(f"Buffer encryption failed: {error_msg} (code: {result})")

def call_hybrid_cpabe_encrypt_and_sign_with_scheme(public_key_file, pqc_private_key_file, plaintext_file, policy, ciphertext_file, scheme=CPABE_SCHEME_COVERCRYPT):
    result = abe_lib.hybrid_cpabe_encrypt_and_sign_with_scheme(
        public_key_file.encode('utf-8'), pqc_private_key_file.encode('utf-8'),
        plaintext_file.encode('utf-8'), policy.encode('utf-8'), ciphertext_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Encryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme(public_key: bytes, pqc_priv_key: bytes, plaintext: bytes, policy: str, scheme: int = CPABE_SCHEME_COVERCRYPT) -> bytes:
    pk_arr = (c_ubyte * len(public_key)).from_buffer_copy(public_key)
    pqc_sk_arr = (c_ubyte * len(pqc_priv_key)).from_buffer_copy(pqc_priv_key)
    pt_arr = (c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    ct_ptr = c_ubyte_p()
    ct_len = c_size_t(0)
    result = abe_lib.hybrid_cpabe_encryptBuffer_and_sign_with_scheme(
        pk_arr, len(public_key), pqc_sk_arr, len(pqc_priv_key),
        pt_arr, len(plaintext), policy.encode('utf-8'),
        byref(ct_ptr), byref(ct_len), scheme
    )
    if result == HCPABE_SUCCESS:
        ct_bytes = bytes(ct_ptr[:ct_len.value])
        abe_lib.freeBuffer(ct_ptr)
        return ct_bytes
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        raise RuntimeError(f"Buffer PQC encryption failed: {error_msg} (code: {result})")


"""Python-friendly wrappers for the native C export table.

All C-owned buffers are copied into Python bytes and released with freeBuffer
even if a native call fails. No caller receives a dangling native pointer.
"""
import ctypes
from ctypes import byref, c_size_t, c_ubyte
from .._native import abe_lib, c_ubyte_p, CPABE_SCHEME_COVERCRYPT

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
    """Encrypt with AES-256-GCM using a unique nonce of at least 12 bytes."""
    if len(key) != 32 or len(iv) < 12:
        raise ValueError("Use a 32-byte AES-256 key and a GCM nonce of at least 12 bytes")
    return _run_outputs(abe_lib.aes_gcm_encrypt, _data(key), len(key),
                        _data(iv), len(iv), _data(plaintext), len(plaintext),
                        _data(aad), len(aad))

def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes = b""):
    """Decrypt with the same nonce and AAD used for encryption."""
    if len(key) != 32 or len(iv) < 12:
        raise ValueError("Use a 32-byte AES-256 key and a GCM nonce of at least 12 bytes")
    return _run_outputs(abe_lib.aes_gcm_decrypt, _data(key), len(key),
                        _data(iv), len(iv), _data(ciphertext), len(ciphertext),
                        _data(aad), len(aad))

def get_version():
    return abe_lib.getVersion().decode("utf-8")

def get_error_message(error_code: int):
    msg = abe_lib.getErrorMessage(error_code)
    return msg.decode("utf-8") if msg else ""


__all__ = ['call_setup', 'call_generate_secret_key', 'call_hybrid_cpabe_encrypt', 'call_hybrid_cpabe_decrypt', 'call_hybrid_cpabe_encryptBuffer', 'call_hybrid_cpabe_decryptBuffer', 'call_hybrid_cpabe_setup_with_pqc', 'call_hybrid_cpabe_encrypt_and_sign', 'call_hybrid_cpabe_decrypt_and_verify', 'call_hybrid_cpabe_encryptBuffer_and_sign', 'call_hybrid_cpabe_decryptBuffer_and_verify', 'call_setup_with_scheme', 'call_hybrid_cpabe_setup_with_pqc_scheme', 'call_generate_secret_key_with_scheme', 'call_hybrid_cpabe_encrypt_with_scheme', 'call_hybrid_cpabe_encryptBuffer_with_scheme', 'call_hybrid_cpabe_encrypt_and_sign_with_scheme', 'call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme', 'CPABE_SCHEME_AC17', 'CPABE_SCHEME_TKN20', 'CPABE_SCHEME_COVERCRYPT', 'HCPABE_SUCCESS', 'HCPABE_ERR_FILE_NOT_FOUND', 'HCPABE_ERR_INVALID_KEY', 'HCPABE_ERR_POLICY_MISMATCH', 'HCPABE_ERR_CRYPTO_FAILED', 'HCPABE_ERR_INVALID_PARAM', 'HCPABE_ERR_MEMORY', 'HCPABE_ERR_UNSUPPORTED_FORMAT', 'HCPABE_ERR_VERSION_MISMATCH', 'HCPABE_ERR_SIGNATURE_INVALID', 'setup_buffer', 'setup_buffer_with_pqc', 'genkey_buffer', 'covercrypt_add_attribute', 'covercrypt_add_dimension', 'covercrypt_add_attribute_buffer', 'covercrypt_add_dimension_buffer', 'ml_dsa_87_generate_keypair', 'ml_dsa_87_sign', 'ml_dsa_87_verify', 'aes_gcm_encrypt', 'aes_gcm_decrypt', 'get_version', 'get_error_message']
