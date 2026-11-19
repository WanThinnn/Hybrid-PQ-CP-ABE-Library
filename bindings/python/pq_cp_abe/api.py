"""Python callable wrappers around the native C ABI (existing API preserved)."""
import ctypes
from ctypes import c_ubyte, c_size_t, byref

from ._native import (
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

# Python functions wrapping C++ library functions
def call_setup(path_to_save_file):
    result = abe_lib.setup(path_to_save_file.encode('utf-8'))
    if result == HCPABE_SUCCESS:
        print(f"Setup completed successfully!")
        print(f"   Files created in: {path_to_save_file}/")
        print(f"   - cpabe_msk.key (Master Secret Key)")
        print(f"   - cpabe_pk.key  (Public Parameters)")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Setup failed: {error_msg} (code: {result})")
    return result

def call_generate_secret_key(master_key_file, attributes, private_key_file):
    result = abe_lib.generateSecretKey(master_key_file.encode('utf-8'),
                                        attributes.encode('utf-8'),
                                        private_key_file.encode('utf-8'))
    if result == HCPABE_SUCCESS:
        print(f"Secret key generated successfully!")
        print(f"   Attributes: {attributes}")
        print(f"   Output: {private_key_file}")
    else:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Key generation failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encrypt(public_key_file, plaintext_file, policy, ciphertext_file):
    result = abe_lib.hybrid_cpabe_encrypt(public_key_file.encode('utf-8'),
                                   plaintext_file.encode('utf-8'),
                                   policy.encode('utf-8'),
                                   ciphertext_file.encode('utf-8'))
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

def call_hybrid_cpabe_encryptBuffer(public_key: bytes, plaintext: bytes, policy: str) -> bytes:
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
def call_hybrid_cpabe_setup_with_pqc(path_to_save_file):
    result = abe_lib.hybrid_cpabe_setup_with_pqc(path_to_save_file.encode('utf-8'))
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

def call_hybrid_cpabe_encrypt_and_sign(public_key_file, pqc_private_key_file, plaintext_file, policy, ciphertext_file):
    result = abe_lib.hybrid_cpabe_encrypt_and_sign(
        public_key_file.encode('utf-8'),
        pqc_private_key_file.encode('utf-8'),
        plaintext_file.encode('utf-8'),
        policy.encode('utf-8'),
        ciphertext_file.encode('utf-8')
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

def call_hybrid_cpabe_encryptBuffer_and_sign(public_key: bytes, pqc_priv_key: bytes, plaintext: bytes, policy: str) -> bytes:
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
def call_setup_with_scheme(path_to_save_file, scheme=CPABE_SCHEME_AC17):
    result = abe_lib.setup_with_scheme(path_to_save_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Setup failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_setup_with_pqc_scheme(path_to_save_file, scheme=CPABE_SCHEME_AC17):
    result = abe_lib.hybrid_cpabe_setup_with_pqc_scheme(path_to_save_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"PQC Setup failed: {error_msg} (code: {result})")
    return result

def call_generate_secret_key_with_scheme(master_key_file, attributes, private_key_file, scheme=CPABE_SCHEME_AC17):
    result = abe_lib.generateSecretKey_with_scheme(master_key_file.encode('utf-8'),
                                        attributes.encode('utf-8'),
                                        private_key_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Key generation failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encrypt_with_scheme(public_key_file, plaintext_file, policy, ciphertext_file, scheme=CPABE_SCHEME_AC17):
    result = abe_lib.hybrid_cpabe_encrypt_with_scheme(public_key_file.encode('utf-8'),
                                   plaintext_file.encode('utf-8'),
                                   policy.encode('utf-8'),
                                   ciphertext_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Encryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encryptBuffer_with_scheme(public_key: bytes, plaintext: bytes, policy: str, scheme: int = CPABE_SCHEME_AC17) -> bytes:
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

def call_hybrid_cpabe_encrypt_and_sign_with_scheme(public_key_file, pqc_private_key_file, plaintext_file, policy, ciphertext_file, scheme=CPABE_SCHEME_AC17):
    result = abe_lib.hybrid_cpabe_encrypt_and_sign_with_scheme(
        public_key_file.encode('utf-8'), pqc_private_key_file.encode('utf-8'),
        plaintext_file.encode('utf-8'), policy.encode('utf-8'), ciphertext_file.encode('utf-8'), scheme)
    if result != HCPABE_SUCCESS:
        error_msg = abe_lib.getErrorMessage(result).decode('utf-8')
        print(f"Encryption failed: {error_msg} (code: {result})")
    return result

def call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme(public_key: bytes, pqc_priv_key: bytes, plaintext: bytes, policy: str, scheme: int = CPABE_SCHEME_AC17) -> bytes:
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
