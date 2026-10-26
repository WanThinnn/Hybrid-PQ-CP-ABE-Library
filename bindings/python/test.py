import os
import sys

# Ensure module in the same directory can be imported
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import hybrid_cpabe as abe
import base64

def load_base64_key(file_path):
    with open(file_path, "r") as f:
        content = f.read()
    lines = content.split('\n')
    base64_data = ""
    for line in lines:
        line = line.strip()
        if not line or line.startswith("-----BEGIN") or line.startswith("-----END"):
            continue
        base64_data += line
    return base64.b64decode(base64_data)

def run_scheme_tests(scheme, scheme_name):
    print("=" * 60)
    print(f"STARTING FULL LOGIC TEST FOR SCHEME: {scheme_name}")
    print("=" * 60)

    # 1. Prepare test directory and files
    test_dir = os.path.join(script_dir, f"test_data_{scheme_name.lower()}")
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)

    msk_file = os.path.join(test_dir, "cpabe_msk.key")
    pk_file = os.path.join(test_dir, "cpabe_pk.key")
    pqc_sk_file = os.path.join(test_dir, "pqc_sk.key")
    pqc_pk_file = os.path.join(test_dir, "pqc_pk.key")
    sk_file = os.path.join(test_dir, "alice.key")
    
    pt_file = os.path.join(test_dir, "plaintext.txt")
    ct_file = os.path.join(test_dir, "ciphertext.enc")
    rt_file = os.path.join(test_dir, "recovered.txt")
    
    pqc_ct_file = os.path.join(test_dir, "ciphertext_pqc.enc")
    pqc_rt_file = os.path.join(test_dir, "recovered_pqc.txt")

    # Create a sample text file for encryption
    with open(pt_file, "w", encoding="utf-8") as f:
        f.write("Hello, this is top secret data that needs to be encrypted by Hybrid CP-ABE!")

    policy = "admin and it"
    attributes = "admin it security"
    
    print("\n[1/5] TEST SETUP PQC (Generate both classic and ML-DSA keys)")
    # Call PQC setup to generate all 4 keys
    res = abe.call_hybrid_cpabe_setup_with_pqc_scheme(test_dir, scheme)
    assert res == abe.HCPABE_SUCCESS, "Setup PQC failed!"

    print("\n[2/5] TEST GENERATE SECRET KEY")
    res = abe.call_generate_secret_key_with_scheme(msk_file, attributes, sk_file, scheme)
    assert res == abe.HCPABE_SUCCESS, "Generate SK failed!"

    print("\n[3/5] TEST FILE-BASED OPERATIONS (Classic)")
    print(" -> Encrypting...")
    res = abe.call_hybrid_cpabe_encrypt_with_scheme(pk_file, pt_file, policy, ct_file, scheme)
    assert res == abe.HCPABE_SUCCESS, "File Encrypt failed!"
    
    print(" -> Decrypting...")
    res = abe.call_hybrid_cpabe_decrypt(sk_file, ct_file, rt_file)
    assert res == abe.HCPABE_SUCCESS, "File Decrypt failed!"
    
    with open(rt_file, "r", encoding="utf-8") as f:
        recovered_text = f.read()
    print(f" -> Recovered Text: {recovered_text}")

    print("\n[4/5] TEST FILE-BASED PQC (Encrypt & Quantum Sign)")
    print(" -> Encrypting & Signing...")
    res = abe.call_hybrid_cpabe_encrypt_and_sign_with_scheme(pk_file, pqc_sk_file, pt_file, policy, pqc_ct_file, scheme)
    assert res == abe.HCPABE_SUCCESS, "PQC File Encrypt failed!"
    
    print(" -> Decrypting & Verifying...")
    res = abe.call_hybrid_cpabe_decrypt_and_verify(sk_file, pqc_pk_file, pqc_ct_file, pqc_rt_file)
    assert res == abe.HCPABE_SUCCESS, "PQC File Decrypt failed!"

    with open(pqc_rt_file, "r", encoding="utf-8") as f:
        recovered_pqc_text = f.read()
    print(f" -> Recovered PQC Text: {recovered_pqc_text}")

    print("\n[5/5] TEST BUFFER-BASED OPERATIONS (In-Memory)")
    # Load keys into memory (Base64 decode is required because files are stored as PEM)
    pk_bytes = load_base64_key(pk_file)
    sk_bytes = load_base64_key(sk_file)
    pqc_sk_bytes = load_base64_key(pqc_sk_file)
    pqc_pk_bytes = load_base64_key(pqc_pk_file)
    
    pt_bytes = "This is a message encrypted directly in RAM!".encode('utf-8')
    
    print(" -> Classic Buffer Encrypt & Decrypt...")
    ct_bytes = abe.call_hybrid_cpabe_encryptBuffer_with_scheme(pk_bytes, pt_bytes, policy, scheme)
    rt_bytes = abe.call_hybrid_cpabe_decryptBuffer(sk_bytes, ct_bytes)
    assert rt_bytes == pt_bytes, "Classic buffer mismatch!"
    print(f"    Success! Decrypted to: {rt_bytes.decode('utf-8')}")

    print(" -> PQC Buffer Encrypt/Sign & Decrypt/Verify...")
    ct_pqc_bytes = abe.call_hybrid_cpabe_encryptBuffer_and_sign_with_scheme(pk_bytes, pqc_sk_bytes, pt_bytes, policy, scheme)
    rt_pqc_bytes = abe.call_hybrid_cpabe_decryptBuffer_and_verify(sk_bytes, pqc_pk_bytes, ct_pqc_bytes)
    assert rt_pqc_bytes == pt_bytes, "PQC buffer mismatch!"
    print(f"    Success! Decrypted to: {rt_pqc_bytes.decode('utf-8')}")

    print("\n" + "=" * 60)
    print(f"ALL TESTS FOR SCHEME {scheme_name} PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_scheme_tests(abe.CPABE_SCHEME_AC17, "AC17")
    print("\n\n")
    run_scheme_tests(abe.CPABE_SCHEME_TKN20, "TKN20")
