#!/usr/bin/env bash
# no set -e — individual failures must not abort suite

EXEC="./build_linux/main"
TC="test_case"
PASS=0
FAIL=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo "================================================================"
echo " Hybrid CP-ABE Full Test Suite (Linux/macOS)"
echo "================================================================"

mkdir -p "$TC/tkn20" "$TC/pqc" "$TC/pqc_tkn20" "$TC/buf"
echo "This is a secret message for testing Hybrid CP-ABE!" > "$TC/plaintext.txt"

# ----------------------------------------------------------------
run() {
    local label="$1"; shift
    local out; out=$("$@" 2>&1); local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "  ${GREEN}[PASS]${NC} $label"; PASS=$((PASS+1))
    else
        echo -e "  ${RED}[FAIL]${NC} $label (exit $rc)"
        echo -e "         ${YELLOW}=> $out${NC}"; FAIL=$((FAIL+1))
    fi
}
run_visible() {
    local label="$1"; shift; "$@"; local rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "  ${GREEN}[PASS]${NC} $label"; PASS=$((PASS+1))
    else
        echo -e "  ${RED}[FAIL]${NC} $label (exit $rc)"; FAIL=$((FAIL+1))
    fi
}
diff_check() {
    local label="$1" f1="$2" f2="$3"
    if diff -q "$f1" "$f2" >/dev/null 2>&1; then
        echo -e "  ${GREEN}[PASS]${NC} $label"; PASS=$((PASS+1))
    else
        echo -e "  ${RED}[FAIL]${NC} $label (content differs)"; FAIL=$((FAIL+1))
    fi
}

# ================================================================
# 1. VERSION / HELP
# ================================================================
echo; echo "--- [1] Version / Help ---"
run "version"   $EXEC version
run "--version" $EXEC --version
run "help"      $EXEC help

# ================================================================
# 2. SETUP (all variants)
#   ac17       -> test_case/cpabe_msk.key + cpabe_pk.key
#   tkn20      -> test_case/tkn20/cpabe_msk.key + cpabe_pk.key
#   ac17+pqc   -> test_case/pqc/cpabe_msk.key + cpabe_pk.key + pqc_sk.key + pqc_pk.key
#   tkn20+pqc  -> test_case/pqc_tkn20/cpabe_msk.key + cpabe_pk.key + pqc_sk.key + pqc_pk.key
# ================================================================
echo; echo "--- [2] Setup ---"
run "setup ac17"        $EXEC setup --scheme ac17  "$TC"
run "setup tkn20"       $EXEC setup --scheme tkn20 "$TC/tkn20"
run "setup ac17+pqc"    $EXEC setup --scheme ac17  --pqc "$TC/pqc"
run "setup tkn20+pqc"   $EXEC setup --scheme tkn20 --pqc "$TC/pqc_tkn20"

# ================================================================
# 3. GENKEY (file-based, all schemes)
# ================================================================
echo; echo "--- [3] GenKey ---"
run "genkey ac17"   $EXEC genkey --scheme ac17  "$TC/cpabe_msk.key"            "A B C"    "$TC/sk_ac17.key"
run "genkey tkn20"  $EXEC genkey --scheme tkn20 "$TC/tkn20/cpabe_msk.key"      "admin it" "$TC/tkn20/sk_tkn20.key"
# Keys for PQC decrypt (must be generated against the same MSK used for PQC encrypt)
$EXEC genkey --scheme ac17  "$TC/pqc/cpabe_msk.key"        "A B C"    "$TC/pqc/sk_ac17.key"        >/dev/null 2>&1
$EXEC genkey --scheme tkn20 "$TC/pqc_tkn20/cpabe_msk.key"  "admin it" "$TC/pqc_tkn20/sk_tkn20.key" >/dev/null 2>&1

# ================================================================
# 4. ENCRYPT / DECRYPT  ac17
# ================================================================
echo; echo "--- [4] Encrypt/Decrypt ac17 ---"
run "encrypt ac17" $EXEC encrypt --scheme ac17 \
    "$TC/cpabe_pk.key" "$TC/plaintext.txt" "((A and C) or E)" "$TC/ct_ac17.bin"
run "decrypt ac17" $EXEC decrypt \
    "$TC/sk_ac17.key" "$TC/ct_ac17.bin" "$TC/recovered_ac17.txt"
diff_check "content match ac17" "$TC/plaintext.txt" "$TC/recovered_ac17.txt"

# ================================================================
# 5. ENCRYPT / DECRYPT  tkn20
# ================================================================
echo; echo "--- [5] Encrypt/Decrypt tkn20 ---"
run "encrypt tkn20" $EXEC encrypt --scheme tkn20 \
    "$TC/tkn20/cpabe_pk.key" "$TC/plaintext.txt" "admin and it" "$TC/ct_tkn20.bin"
run "decrypt tkn20" $EXEC decrypt \
    "$TC/tkn20/sk_tkn20.key" "$TC/ct_tkn20.bin" "$TC/recovered_tkn20.txt"
diff_check "content match tkn20" "$TC/plaintext.txt" "$TC/recovered_tkn20.txt"

# ================================================================
# 6. ENCRYPT / DECRYPT  ac17 + PQC
# ================================================================
echo; echo "--- [6] Encrypt/Decrypt ac17+PQC ---"
run "encrypt ac17+pqc" $EXEC encrypt --scheme ac17 --pqc \
    "$TC/pqc/cpabe_pk.key" "$TC/pqc/pqc_sk.key" \
    "$TC/plaintext.txt" "((A and C) or E)" "$TC/ct_pqc_ac17.bin"
run "decrypt ac17+pqc" $EXEC decrypt --pqc \
    "$TC/pqc/sk_ac17.key" "$TC/pqc/pqc_pk.key" \
    "$TC/ct_pqc_ac17.bin" "$TC/recovered_pqc_ac17.txt"
diff_check "content match ac17+pqc" "$TC/plaintext.txt" "$TC/recovered_pqc_ac17.txt"

# ================================================================
# 7. ENCRYPT / DECRYPT  tkn20 + PQC
# ================================================================
echo; echo "--- [7] Encrypt/Decrypt tkn20+PQC ---"
run "encrypt tkn20+pqc" $EXEC encrypt --scheme tkn20 --pqc \
    "$TC/pqc_tkn20/cpabe_pk.key" "$TC/pqc_tkn20/pqc_sk.key" \
    "$TC/plaintext.txt" "admin and it" "$TC/ct_pqc_tkn20.bin"
run "decrypt tkn20+pqc" $EXEC decrypt --pqc \
    "$TC/pqc_tkn20/sk_tkn20.key" "$TC/pqc_tkn20/pqc_pk.key" \
    "$TC/ct_pqc_tkn20.bin" "$TC/recovered_pqc_tkn20.txt"
diff_check "content match tkn20+pqc" "$TC/plaintext.txt" "$TC/recovered_pqc_tkn20.txt"

# ================================================================
# 8. SETUP_BUFFER / GENKEY_BUFFER
#
# Flow in main.cpp genkey_buffer:
#   reads file → Base64Decoder → decodedMsk → genkeyBuffer(decodedMsk)
#
# Flow in ac17_genkeyBuffer(mskBuffer):
#   decodeBase64(mskBuffer) → JSON string → rabe_ac17_master_key_from_json()
#
# So the file must contain: Base64( Base64(JSON) )
# i.e. double-encoded.
#
# setup_buffer prints: Base64(JSON)  (single encoded)
# main.cpp reads file → decodes once → passes Base64(JSON) to genkeyBuffer
# genkeyBuffer decodes again → gets JSON → OK
#
# Therefore file = the raw Base64(JSON) line from setup_buffer output.
# We just need to capture it correctly (no extra encoding).
#
# The issue was awk running setup_buffer AGAIN (different keys).
# Fix: run once, tee to file, parse that file.
# ================================================================
echo; echo "--- [8] Setup_Buffer / GenKey_Buffer ---"

# ---- ac17 ----
$EXEC setup_buffer --scheme ac17 2>/dev/null > "$TC/buf/setup_ac17.txt"
run "setup_buffer ac17" test -s "$TC/buf/setup_ac17.txt"

# Extract lines: grep -A1 gets the header + next line; second grep removes header
grep -A1 "PUBLIC KEY"        "$TC/buf/setup_ac17.txt" | grep -v "PUBLIC KEY"        | grep -v "^--$" > "$TC/buf/pk_ac17.key"
grep -A1 "MASTER SECRET KEY" "$TC/buf/setup_ac17.txt" | grep -v "MASTER SECRET KEY" | grep -v "^--$" > "$TC/buf/msk_ac17.key"

# Verify files are non-empty
run "buf_msk_ac17 extracted" test -s "$TC/buf/msk_ac17.key"

run "genkey_buffer ac17"  $EXEC genkey_buffer --scheme ac17  "$TC/buf/msk_ac17.key" "A B C"

# ---- tkn20 ----
$EXEC setup_buffer --scheme tkn20 2>/dev/null > "$TC/buf/setup_tkn20.txt"
run "setup_buffer tkn20" test -s "$TC/buf/setup_tkn20.txt"

grep -A1 "PUBLIC KEY"        "$TC/buf/setup_tkn20.txt" | grep -v "PUBLIC KEY"        | grep -v "^--$" > "$TC/buf/pk_tkn20.key"
grep -A1 "MASTER SECRET KEY" "$TC/buf/setup_tkn20.txt" | grep -v "MASTER SECRET KEY" | grep -v "^--$" > "$TC/buf/msk_tkn20.key"

run "buf_msk_tkn20 extracted" test -s "$TC/buf/msk_tkn20.key"

run "genkey_buffer tkn20" $EXEC genkey_buffer --scheme tkn20 "$TC/buf/msk_tkn20.key" "admin it"

# ================================================================
# 9. ENCRYPT_BUFFER / DECRYPT_BUFFER  (file-based keys, all schemes)
# ================================================================
echo; echo "--- [9] EncryptBuffer/DecryptBuffer ac17 ---"
run "encrypt_buffer ac17" $EXEC encrypt_buffer --scheme ac17 \
    "$TC/cpabe_pk.key" "Hello from buffer ac17!" "((A and C) or E)" "$TC/ct_buf_ac17.bin"
run_visible "decrypt_buffer ac17" $EXEC decrypt_buffer \
    "$TC/sk_ac17.key" "$TC/ct_buf_ac17.bin"

echo; echo "--- [9] EncryptBuffer/DecryptBuffer tkn20 ---"
run "encrypt_buffer tkn20" $EXEC encrypt_buffer --scheme tkn20 \
    "$TC/tkn20/cpabe_pk.key" "Hello from buffer tkn20!" "admin and it" "$TC/ct_buf_tkn20.bin"
run_visible "decrypt_buffer tkn20" $EXEC decrypt_buffer \
    "$TC/tkn20/sk_tkn20.key" "$TC/ct_buf_tkn20.bin"

# ================================================================
# 10. ENCRYPT_BUFFER+SIGN / DECRYPT_BUFFER+VERIFY  (buffer pk from setup_buffer)
# ================================================================
echo; echo "--- [10] EncryptBuffer+Sign / DecryptBuffer+Verify ac17 ---"
# For buffer PQC we need to use buf pk + a pqc key; reuse file-based pqc keys for simplicity
run "encrypt_buffer ac17+pqc (buf pk)" $EXEC encrypt_buffer --scheme ac17 --pqc \
    "$TC/buf/pk_ac17.key" "$TC/pqc/pqc_sk.key" \
    "Hello signed buffer!" "((A and C) or E)" "$TC/ct_buf_pqc_ac17.bin"
# Decrypt needs an SK generated from buf_msk, but buf_msk → different keypair than pqc/cpabe_msk.
# So use regular file-based flow for decrypt_buffer+verify instead.
run "decrypt_buffer ac17+pqc" $EXEC decrypt_buffer --pqc \
    "$TC/sk_ac17.key" "$TC/pqc/pqc_pk.key" "$TC/ct_buf_pqc_ac17.bin"

echo; echo "--- [10] EncryptBuffer+Sign / DecryptBuffer+Verify tkn20 ---"
run "encrypt_buffer tkn20+pqc (buf pk)" $EXEC encrypt_buffer --scheme tkn20 --pqc \
    "$TC/buf/pk_tkn20.key" "$TC/pqc_tkn20/pqc_sk.key" \
    "Hello signed buffer tkn20!" "admin and it" "$TC/ct_buf_pqc_tkn20.bin"
run "decrypt_buffer tkn20+pqc" $EXEC decrypt_buffer --pqc \
    "$TC/tkn20/sk_tkn20.key" "$TC/pqc_tkn20/pqc_pk.key" "$TC/ct_buf_pqc_tkn20.bin"

# ================================================================
# SUMMARY
# ================================================================
echo
echo "================================================================"
echo " Results: $PASS PASSED  /  $FAIL FAILED"
echo "================================================================"
[ "$FAIL" -gt 0 ] && { echo " Some tests FAILED."; exit 1; } || { echo " All tests PASSED!"; exit 0; }