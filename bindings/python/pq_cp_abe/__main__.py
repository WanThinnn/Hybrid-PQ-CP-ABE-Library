"""Run the existing command-line interface with python -m pq_cp_abe."""
import sys
from .api import *
from ._native import abe_lib

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
        print("  --test                                   - Test all 33 native C exports")
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

    if mode == "--test":
        if len(sys.argv) != 2:
            print(f"Usage: python {sys.argv[0]} --test")
            sys.exit(2)
        from .selftest import main as run_selftest
        sys.exit(run_selftest())

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
