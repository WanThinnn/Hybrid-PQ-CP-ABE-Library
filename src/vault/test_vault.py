import requests
import base64
import json

VAULT_ADDR = "http://127.0.0.1:8201"
VAULT_TOKEN = "root"

headers = {
    "X-Vault-Token": VAULT_TOKEN,
    "Content-Type": "application/json"
}

def setup_abe(scheme):
    print(f"[*] Setting up ABE ({scheme.upper()})...")
    resp = requests.put(f"{VAULT_ADDR}/v1/abe/setup", headers=headers, json={"scheme": scheme})
    resp.raise_for_status()
    data = resp.json()["data"]
    print("  + Setup successful")
    return data["public_key"]

def gen_key(attributes, scheme):
    print(f"[*] Generating secret key for attributes: {attributes}")
    resp = requests.put(f"{VAULT_ADDR}/v1/abe/genkey", headers=headers, json={"scheme": scheme, "attributes": attributes})
    resp.raise_for_status()
    data = resp.json()["data"]
    print("  + Key generation successful")
    return data["secret_key"]

def encrypt(plaintext, policy, public_key, scheme):
    print(f"[*] Encrypting message for policy: {policy}")
    pt_b64 = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")
    resp = requests.put(f"{VAULT_ADDR}/v1/abe/encrypt", headers=headers, json={
        "scheme": scheme,
        "plaintext": pt_b64,
        "policy": policy,
        "public_key": public_key
    })
    resp.raise_for_status()
    data = resp.json()["data"]
    print("  + Encryption successful")
    return data["ciphertext"]

def decrypt(ciphertext, secret_key, scheme):
    print("[*] Decrypting message...")
    resp = requests.put(f"{VAULT_ADDR}/v1/abe/decrypt", headers=headers, json={
        "scheme": scheme,
        "ciphertext": ciphertext,
        "secret_key": secret_key
    })
    resp.raise_for_status()
    data = resp.json()["data"]
    pt_b64 = data["plaintext"]
    plaintext = base64.b64decode(pt_b64).decode("utf-8")
    print("  + Decryption successful")
    return plaintext

def test_scheme(scheme):
    print(f"\n======================================")
    print(f"    TESTING SCHEME: {scheme.upper()}")
    print(f"======================================")
    try:
        pk = setup_abe(scheme)
        
        # 1. Generate keys for different users
        sk_admin = gen_key("role:admin", scheme)
        sk_guest = gen_key("role:guest", scheme)
        
        # 2. Encrypt a message meant only for admins
        message = f"Hello from Python! This is a highly confidential message encrypted with {scheme.upper()}."
        policy = "role:admin"
        ct = encrypt(message, policy, pk, scheme)
        
        # 3. Admin attempts to decrypt
        print("\n[*] Admin attempting to decrypt...")
        pt1 = decrypt(ct, sk_admin, scheme)
        print(f"  -> Result: {pt1}")
        
        # 4. Guest attempts to decrypt
        print("\n[*] Guest attempting to decrypt (should fail)...")
        try:
            pt2 = decrypt(ct, sk_guest, scheme)
            print(f"  -> Result: {pt2}")
        except requests.exceptions.HTTPError as e:
            print(f"  -> Decryption failed as expected: {e.response.json()['errors']}")
            
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_scheme("tkn20")
    test_scheme("ac17")

