import ctypes
from ctypes import c_char_p, POINTER, c_ubyte, c_size_t, byref
import sys
import os
import platform

# Path to the library (same directory as this script)
script_dir = os.path.dirname(os.path.abspath(__file__))

# Select the library name based on the operating system
system = platform.system()
if system == "Windows":
    lib_name = "libhybrid-pq-cp-abe.dll"
elif system == "Darwin":
    lib_name = "libhybrid-pq-cp-abe.dylib" 
else:
    lib_name = "libhybrid-pq-cp-abe.so"

lib_path = os.path.join(script_dir, "lib",lib_name)

if not os.path.exists(lib_path):
    print(f"Error: Library not found at {lib_path}")
    print(f"   Make sure {lib_name} is in the same directory as this script.")
    sys.exit(1)

# Load the shared library (.dll/.so)
abe_lib = ctypes.CDLL(lib_path)

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

# Error codes
HCPABE_SUCCESS = 0
HCPABE_ERR_FILE_NOT_FOUND = -1
HCPABE_ERR_INVALID_KEY = -2
HCPABE_ERR_POLICY_MISMATCH = -3
HCPABE_ERR_CRYPTO_FAILED = -4

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

# Main function to handle CLI in Python
if __name__ == "__main__":
    # Print version info
    version = abe_lib.getVersion().decode('utf-8')
    print(f"Hybrid CP-ABE Library v{version} (Python Wrapper)")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} [setup|genkey|encrypt|decrypt]")
        print()
        print("Commands:")
        print("  setup   <path>                          - Generate master & public keys")
        print("  genkey   <msk> <attrs> <out>            - Generate secret key")
        print("  encrypt  <pk> <file> <policy> <out>     - Encrypt file")
        print("  decrypt  <sk> <file> <out>              - Decrypt file")
        print("  test-buf <pk_file> <sk_file>            - Test buffer encryption")
        print("  --- PQC Commands ---")
        print("  setup-pqc <path>                        - Generate keys + ML-DSA keys")
        print("  encrypt-pqc <pk> <pqc_sk> <file> <policy> <out> - Encrypt & Sign")
        print("  decrypt-pqc <sk> <pqc_pk> <file> <out>          - Decrypt & Verify")
        print()
        print("Examples:")
        print(f"  python {sys.argv[0]} setup ./keys")
        print(f"  python {sys.argv[0]} setup-pqc ./keys")
        print(f"  python {sys.argv[0]} encrypt-pqc ./keys/cpabe_pk.key ./keys/pqc_sk.key data.txt \"(admin and it)\" data.enc")
        sys.exit(1)

    mode = sys.argv[1]

    try:
        if mode == "setup":
            if len(sys.argv) != 3:
                print(f"Usage: python {sys.argv[0]} setup <path_to_save_keys>")
                sys.exit(1)
            path = sys.argv[2]
            result = call_setup(path)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "setup-pqc":
            if len(sys.argv) != 3:
                print(f"Usage: python {sys.argv[0]} setup-pqc <path_to_save_keys>")
                sys.exit(1)
            path = sys.argv[2]
            result = call_hybrid_cpabe_setup_with_pqc(path)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "genkey":
            if len(sys.argv) != 5:
                print(f"Usage: python {sys.argv[0]} genkey <master_key_file> <attributes> <private_key_file>")
                print(f"Example: python {sys.argv[0]} genkey ./keys/cpabe_msk.key \"admin it security\" ./keys/alice.key")
                sys.exit(1)
            master_key_file = sys.argv[2]
            attributes = sys.argv[3]
            private_key_file = sys.argv[4]
            result = call_generate_secret_key(master_key_file, attributes, private_key_file)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "encrypt":
            if len(sys.argv) != 6:
                print(f"Usage: python {sys.argv[0]} encrypt <public_key_file> <plaintext_file> <policy> <ciphertext_file>")
                print(f"Example: python {sys.argv[0]} encrypt ./keys/cpabe_pk.key data.txt \"(admin and it)\" data.enc")
                sys.exit(1)
            public_key_file = sys.argv[2]
            plaintext_file = sys.argv[3]
            policy = sys.argv[4]
            ciphertext_file = sys.argv[5]
            result = call_hybrid_cpabe_encrypt(public_key_file, plaintext_file, policy, ciphertext_file)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "encrypt-pqc":
            if len(sys.argv) != 7:
                print(f"Usage: python {sys.argv[0]} encrypt-pqc <pk> <pqc_sk> <file> <policy> <out>")
                sys.exit(1)
            result = call_hybrid_cpabe_encrypt_and_sign(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "decrypt":
            if len(sys.argv) != 5:
                print(f"Usage: python {sys.argv[0]} decrypt <private_key_file> <ciphertext_file> <recovertext_file>")
                print(f"Example: python {sys.argv[0]} decrypt ./keys/alice.key data.enc data.dec")
                sys.exit(1)
            private_key_file = sys.argv[2]
            ciphertext_file = sys.argv[3]
            recovertext_file = sys.argv[4]
            result = call_hybrid_cpabe_decrypt(private_key_file, ciphertext_file, recovertext_file)
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "decrypt-pqc":
            if len(sys.argv) != 6:
                print(f"Usage: python {sys.argv[0]} decrypt-pqc <sk> <pqc_pk> <file> <out>")
                sys.exit(1)
            result = call_hybrid_cpabe_decrypt_and_verify(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
            sys.exit(0 if result == HCPABE_SUCCESS else 1)
            
        elif mode == "test-buf":
            if len(sys.argv) != 4:
                print(f"Usage: python {sys.argv[0]} test-buf <public_key_file> <private_key_file>")
                sys.exit(1)
            
            with open(sys.argv[2], "rb") as f:
                pk = f.read()
            with open(sys.argv[3], "rb") as f:
                sk = f.read()
                
            plaintext = b"Hello, this is a test for Hybrid CP-ABE buffer encryption!"
            policy = "admin and it"
            
            print(f"Original plaintext: {plaintext.decode('utf-8')}")
            print(f"Policy: {policy}")
            print("Encrypting buffer...")
            ct = call_hybrid_cpabe_encryptBuffer(pk, plaintext, policy)
            print(f"Encrypted! Ciphertext size: {len(ct)} bytes")
            
            print("Decrypting buffer...")
            pt = call_hybrid_cpabe_decryptBuffer(sk, ct)
            print(f"Recovered plaintext: {pt.decode('utf-8')}")
            
            if pt == plaintext:
                print("Buffer encryption/decryption test PASSED!")
                sys.exit(0)
            else:
                print("Buffer test FAILED!")
                sys.exit(1)
            
        else:
            print(f"Invalid command: {mode}")
            print(f"Valid commands: setup, genkey, encrypt, decrypt, test-buf")
            sys.exit(1)
            
    except Exception as ex:
        print(f"Exception: {ex}")
        sys.exit(1)