import os
import sys
import time
import json
import matplotlib.pyplot as plt
import numpy as np
import hashlib
from Crypto.Cipher import AES
import base64

# Charm imports
try:
    from charm.toolbox.pairinggroup import PairingGroup, GT
    from charm.schemes.abenc.ac17 import AC17CPABE
    CHARM_AVAILABLE = True
except ImportError:
    CHARM_AVAILABLE = False
    print("Warning: charm-crypto is not installed or failed to import.")

# Custom library imports
from hybrid_cpabe import (
    call_setup_with_scheme,
    call_generate_secret_key_with_scheme,
    call_hybrid_cpabe_encrypt_with_scheme,
    call_hybrid_cpabe_decrypt,
    call_hybrid_cpabe_encryptBuffer_with_scheme,
    call_hybrid_cpabe_decryptBuffer,
    HCPABE_SUCCESS,
    CPABE_SCHEME_AC17,
    CPABE_SCHEME_TKN20
)

# Constants
ITERATIONS = 500
RESULTS_DIR = "results"
TEMP_DIR = "temp_bench"
POLICY = "(((((ATTR1 AND ATTR2) AND ATTR3) AND (ATTR4 OR ATTR5)) AND ((ATTR6 AND ATTR7) OR (ATTR8 AND ATTR9))) AND (ATTR10 OR ATTR11))"
ATTRIBUTES = "ATTR1 ATTR2 ATTR3 ATTR4 ATTR8 ATTR9 ATTR11 EXTRA1 EXTRA2 EXTRA3 EXTRA4 EXTRA5"
ATTR_LIST = ['ATTR1', 'ATTR2', 'ATTR3', 'ATTR4', 'ATTR8', 'ATTR9', 'ATTR11', 'EXTRA1', 'EXTRA2', 'EXTRA3', 'EXTRA4', 'EXTRA5']
PLAINTEXT_DATA = b"Hello, this is a test for Hybrid CP-ABE benchmarking! Just padding with some more bytes to make it realistic."

def ensure_dirs():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

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

def benchmark_charm():
    if not CHARM_AVAILABLE:
        return None
    
    print("--- Benchmarking Charm Crypto AC17 ---")
    group = PairingGroup('BN254')
    ac17 = AC17CPABE(group_obj=group, assump_size=2)
    
    times = {'setup': 0, 'keygen': 0, 'encrypt': 0, 'decrypt': 0}
    
    # Setup
    start = time.time()
    for _ in range(ITERATIONS):
        (pk, msk) = ac17.setup()
    times['setup'] = (time.time() - start) / ITERATIONS
    
    # Keygen
    start = time.time()
    for _ in range(ITERATIONS):
        sk = ac17.keygen(pk, msk, ATTR_LIST)
    times['keygen'] = (time.time() - start) / ITERATIONS
    
    # Encrypt
    start = time.time()
    for _ in range(ITERATIONS):
        rand_key = os.urandom(1536)
        k = group.random(GT)
        aes_kem_key = hashlib.sha256(group.serialize(k)).digest()
        kem_cipher = AES.new(aes_kem_key, AES.MODE_GCM)
        enc_rand_key, kem_tag = kem_cipher.encrypt_and_digest(rand_key)
        kem_nonce = kem_cipher.nonce
        
        ctxt = ac17.encrypt(pk, k, POLICY)
        
        aes_key = hashlib.sha3_256(rand_key).digest()
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(PLAINTEXT_DATA)
        nonce = cipher.nonce
    times['encrypt'] = (time.time() - start) / ITERATIONS
    
    # Decrypt
    start = time.time()
    for _ in range(ITERATIONS):
        recovered_k = ac17.decrypt(pk, ctxt, sk)
        aes_kem_key_rec = hashlib.sha256(group.serialize(recovered_k)).digest()
        kem_cipher_rec = AES.new(aes_kem_key_rec, AES.MODE_GCM, nonce=kem_nonce)
        recovered_rand_key = kem_cipher_rec.decrypt_and_verify(enc_rand_key, kem_tag)
        aes_key_rec = hashlib.sha3_256(recovered_rand_key).digest()
        cipher_rec = AES.new(aes_key_rec, AES.MODE_GCM, nonce=nonce)
        recovered_msg = cipher_rec.decrypt_and_verify(ct, tag)
    times['decrypt'] = (time.time() - start) / ITERATIONS
    
    if PLAINTEXT_DATA != recovered_msg:
        print("Warning: Charm decryption failed during benchmark!")
        
    return times

def benchmark_custom_file(scheme, scheme_name):
    print(f"--- Benchmarking Custom Library {scheme_name} (File I/O) ---")
    times = {'setup': 0, 'keygen': 0, 'encrypt': 0, 'decrypt': 0}
    
    msk_path = os.path.join(TEMP_DIR, f"cpabe_msk_{scheme_name}.key")
    pk_path = os.path.join(TEMP_DIR, f"cpabe_pk_{scheme_name}.key")
    sk_path = os.path.join(TEMP_DIR, f"user_{scheme_name}.key")
    pt_path = os.path.join(TEMP_DIR, f"data_{scheme_name}.txt")
    ct_path = os.path.join(TEMP_DIR, f"data_{scheme_name}.enc")
    dt_path = os.path.join(TEMP_DIR, f"data_{scheme_name}.dec")
    
    with open(pt_path, "wb") as f:
        f.write(PLAINTEXT_DATA)
        
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_setup_with_scheme(TEMP_DIR, scheme)
        if res != HCPABE_SUCCESS: raise Exception("Setup failed")
    times['setup'] = (time.time() - start) / ITERATIONS
    
    # Rename standard output files to our scheme specific ones
    # (Doing this outside the loop to avoid WinError 5 Access Denied from Antivirus locks)
    import shutil
    shutil.copy(os.path.join(TEMP_DIR, "cpabe_msk.key"), msk_path)
    shutil.copy(os.path.join(TEMP_DIR, "cpabe_pk.key"), pk_path)
    
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_generate_secret_key_with_scheme(msk_path, ATTRIBUTES, sk_path, scheme)
        if res != HCPABE_SUCCESS: raise Exception("Keygen failed")
    times['keygen'] = (time.time() - start) / ITERATIONS
    
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_hybrid_cpabe_encrypt_with_scheme(pk_path, pt_path, POLICY, ct_path, scheme)
        if res != HCPABE_SUCCESS: raise Exception("Encrypt failed")
    times['encrypt'] = (time.time() - start) / ITERATIONS
    
    start = time.time()
    for _ in range(ITERATIONS):
        res = call_hybrid_cpabe_decrypt(sk_path, ct_path, dt_path)
        if res != HCPABE_SUCCESS: raise Exception("Decrypt failed")
    times['decrypt'] = (time.time() - start) / ITERATIONS
    
    return times

def benchmark_custom_buffer(scheme, scheme_name):
    print(f"--- Benchmarking Custom Library {scheme_name} (Buffer) ---")
    times = {'setup': 0, 'keygen': 0, 'encrypt': 0, 'decrypt': 0}
    
    msk_path = os.path.join(TEMP_DIR, "cpabe_msk.key")
    pk_path = os.path.join(TEMP_DIR, "cpabe_pk.key")
    sk_path = os.path.join(TEMP_DIR, "user.key")
    
    call_setup_with_scheme(TEMP_DIR, scheme)
    call_generate_secret_key_with_scheme(msk_path, ATTRIBUTES, sk_path, scheme)
    
    pk_bytes = load_base64_key(pk_path)
    sk_bytes = load_base64_key(sk_path)
    
    start = time.time()
    for _ in range(ITERATIONS):
        ct_bytes = call_hybrid_cpabe_encryptBuffer_with_scheme(pk_bytes, PLAINTEXT_DATA, POLICY, scheme)
    times['encrypt'] = (time.time() - start) / ITERATIONS
    
    start = time.time()
    for _ in range(ITERATIONS):
        pt_bytes = call_hybrid_cpabe_decryptBuffer(sk_bytes, ct_bytes)
    times['decrypt'] = (time.time() - start) / ITERATIONS
    
    if pt_bytes != PLAINTEXT_DATA:
        print("Warning: Custom Buffer decryption failed during benchmark!")
        
    return times

def plot_results(results):
    labels = ['Setup', 'KeyGen', 'Encrypt', 'Decrypt']
    
    charm = results.get('charm')
    ac17_f = results['ac17_file']
    ac17_b = results['ac17_buffer']
    tkn20_f = results['tkn20_file']
    tkn20_b = results['tkn20_buffer']

    charm_means = [
        charm['setup']*1000 if charm else 0, charm['keygen']*1000 if charm else 0,
        charm['encrypt']*1000 if charm else 0, charm['decrypt']*1000 if charm else 0
    ]
    
    ac17_f_means = [ac17_f['setup']*1000, ac17_f['keygen']*1000, ac17_f['encrypt']*1000, ac17_f['decrypt']*1000]
    ac17_b_means = [ac17_f['setup']*1000, ac17_f['keygen']*1000, ac17_b['encrypt']*1000, ac17_b['decrypt']*1000]
    
    tkn20_f_means = [tkn20_f['setup']*1000, tkn20_f['keygen']*1000, tkn20_f['encrypt']*1000, tkn20_f['decrypt']*1000]
    tkn20_b_means = [tkn20_f['setup']*1000, tkn20_f['keygen']*1000, tkn20_b['encrypt']*1000, tkn20_b['decrypt']*1000]

    x = np.arange(len(labels))
    width = 0.15

    fig, ax = plt.subplots(figsize=(12, 6))
    rects1 = ax.bar(x - 2*width, charm_means, width, label='Charm (AC17)')
    rects2 = ax.bar(x - width, ac17_f_means, width, label='AC17 (File I/O)')
    rects3 = ax.bar(x, ac17_b_means, width, label='AC17 (Buffer)')
    rects4 = ax.bar(x + width, tkn20_f_means, width, label='TKN20 (File I/O)')
    rects5 = ax.bar(x + 2*width, tkn20_b_means, width, label='TKN20 (Buffer)')

    ax.set_ylabel('Time (ms)')
    ax.set_title(f'CP-ABE Performance Benchmark (Average over {ITERATIONS} iterations)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            if height > 0:
                ax.annotate(f'{height:.2f}',
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 3),
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=7, rotation=90)

    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)
    autolabel(rects4)
    autolabel(rects5)

    fig.tight_layout()
    chart_path = os.path.join(RESULTS_DIR, 'benchmark_chart.png')
    plt.savefig(chart_path, dpi=300)
    print(f"Chart saved to {chart_path}")
    
    # Encrypt/Decrypt focus
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    enc_dec_labels = ['Encrypt', 'Decrypt']
    x2 = np.arange(len(enc_dec_labels))
    
    c_ed = [charm_means[2], charm_means[3]]
    a17f_ed = [ac17_f_means[2], ac17_f_means[3]]
    a17b_ed = [ac17_b_means[2], ac17_b_means[3]]
    t20f_ed = [tkn20_f_means[2], tkn20_f_means[3]]
    t20b_ed = [tkn20_b_means[2], tkn20_b_means[3]]
    
    rects1_ed = ax2.bar(x2 - 2*width, c_ed, width, label='Charm (AC17)')
    rects2_ed = ax2.bar(x2 - width, a17f_ed, width, label='AC17 (File I/O)')
    rects3_ed = ax2.bar(x2, a17b_ed, width, label='AC17 (Buffer)')
    rects4_ed = ax2.bar(x2 + width, t20f_ed, width, label='TKN20 (File I/O)')
    rects5_ed = ax2.bar(x2 + 2*width, t20b_ed, width, label='TKN20 (Buffer)')
    
    ax2.set_ylabel('Time (ms)')
    ax2.set_title('Encrypt and Decrypt Performance Comparison')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(enc_dec_labels)
    ax2.legend()
    
    autolabel(rects1_ed)
    autolabel(rects2_ed)
    autolabel(rects3_ed)
    autolabel(rects4_ed)
    autolabel(rects5_ed)
    
    fig2.tight_layout()
    chart2_path = os.path.join(RESULTS_DIR, 'encrypt_decrypt_focus_chart.png')
    plt.savefig(chart2_path, dpi=300)
    print(f"Focus chart saved to {chart2_path}")

def main():
    ensure_dirs()
    results = {}
    
    results['charm'] = benchmark_charm()
    results['ac17_file'] = benchmark_custom_file(CPABE_SCHEME_AC17, "AC17")
    results['ac17_buffer'] = benchmark_custom_buffer(CPABE_SCHEME_AC17, "AC17")
    results['tkn20_file'] = benchmark_custom_file(CPABE_SCHEME_TKN20, "TKN20")
    results['tkn20_buffer'] = benchmark_custom_buffer(CPABE_SCHEME_TKN20, "TKN20")
    
    results_path = os.path.join(RESULTS_DIR, "benchmark_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {results_path}")
    
    plot_results(results)

if __name__ == "__main__":
    import builtins
    original_print = builtins.print
    
    def quiet_print(*args, **kwargs):
        if args and isinstance(args[0], str) and (args[0].startswith("---") or args[0].startswith("Chart") or args[0].startswith("Focus") or args[0].startswith("Results") or args[0].startswith("Warning")):
            original_print(*args, **kwargs)
            
    builtins.print = quiet_print
    main()
    builtins.print = original_print
    print("Benchmarking completed successfully!")
