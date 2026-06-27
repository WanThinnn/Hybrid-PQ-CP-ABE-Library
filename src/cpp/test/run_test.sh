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

# Create dedicated directories for each scheme
mkdir -p "$TC/ac17" "$TC/ac17_pqc" "$TC/tkn20" "$TC/tkn20_pqc" "$TC/buf_ac17" "$TC/buf_ac17_pqc" "$TC/buf_tkn20" "$TC/buf_tkn20_pqc"
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
# ================================================================
echo; echo "--- [2] Setup ---"
run "setup ac17"        $EXEC setup --scheme ac17  "$TC/ac17"
run "setup ac17+pqc"    $EXEC setup --scheme ac17  --pqc "$TC/ac17_pqc"
run "setup tkn20"       $EXEC setup --scheme tkn20 "$TC/tkn20"
run "setup tkn20+pqc"   $EXEC setup --scheme tkn20 --pqc "$TC/tkn20_pqc"

# ================================================================
# 3. GENKEY (file-based, all schemes)
# ================================================================
echo; echo "--- [3] GenKey ---"
run "genkey ac17"       $EXEC genkey --scheme ac17  "$TC/ac17/cpabe_msk.key"        "A B C"    "$TC/ac17/sk.key"
$EXEC genkey --scheme ac17  "$TC/ac17_pqc/cpabe_msk.key"    "A B C"    "$TC/ac17_pqc/sk.key" >/dev/null 2>&1
run "genkey tkn20"      $EXEC genkey --scheme tkn20 "$TC/tkn20/cpabe_msk.key"       "admin it" "$TC/tkn20/sk.key"
$EXEC genkey --scheme tkn20 "$TC/tkn20_pqc/cpabe_msk.key"   "admin it" "$TC/tkn20_pqc/sk.key" >/dev/null 2>&1

# ================================================================
# 4. ENCRYPT / DECRYPT  ac17
# ================================================================
echo; echo "--- [4] Encrypt/Decrypt ac17 ---"
run "encrypt ac17" $EXEC encrypt --scheme ac17 "$TC/ac17/cpabe_pk.key" "$TC/plaintext.txt" "((A and C) or E)" "$TC/ac17/ct.bin"
run "decrypt ac17" $EXEC decrypt "$TC/ac17/sk.key" "$TC/ac17/ct.bin" "$TC/ac17/recovered.txt"
diff_check "content match ac17" "$TC/plaintext.txt" "$TC/ac17/recovered.txt"

# ================================================================
# 5. ENCRYPT / DECRYPT  tkn20
# ================================================================
echo; echo "--- [5] Encrypt/Decrypt tkn20 ---"
run "encrypt tkn20" $EXEC encrypt --scheme tkn20 "$TC/tkn20/cpabe_pk.key" "$TC/plaintext.txt" "admin and it" "$TC/tkn20/ct.bin"
run "decrypt tkn20" $EXEC decrypt "$TC/tkn20/sk.key" "$TC/tkn20/ct.bin" "$TC/tkn20/recovered.txt"
diff_check "content match tkn20" "$TC/plaintext.txt" "$TC/tkn20/recovered.txt"

# ================================================================
# 6. ENCRYPT / DECRYPT  ac17 + PQC
# ================================================================
echo; echo "--- [6] Encrypt/Decrypt ac17+PQC ---"
run "encrypt ac17+pqc" $EXEC encrypt --scheme ac17 --pqc "$TC/ac17_pqc/cpabe_pk.key" "$TC/ac17_pqc/pqc_sk.key" "$TC/plaintext.txt" "((A and C) or E)" "$TC/ac17_pqc/ct.bin"
run "decrypt ac17+pqc" $EXEC decrypt --pqc "$TC/ac17_pqc/sk.key" "$TC/ac17_pqc/pqc_pk.key" "$TC/ac17_pqc/ct.bin" "$TC/ac17_pqc/recovered.txt"
diff_check "content match ac17+pqc" "$TC/plaintext.txt" "$TC/ac17_pqc/recovered.txt"

# ================================================================
# 7. ENCRYPT / DECRYPT  tkn20 + PQC
# ================================================================
echo; echo "--- [7] Encrypt/Decrypt tkn20+PQC ---"
run "encrypt tkn20+pqc" $EXEC encrypt --scheme tkn20 --pqc "$TC/tkn20_pqc/cpabe_pk.key" "$TC/tkn20_pqc/pqc_sk.key" "$TC/plaintext.txt" "admin and it" "$TC/tkn20_pqc/ct.bin"
run "decrypt tkn20+pqc" $EXEC decrypt --pqc "$TC/tkn20_pqc/sk.key" "$TC/tkn20_pqc/pqc_pk.key" "$TC/tkn20_pqc/ct.bin" "$TC/tkn20_pqc/recovered.txt"
diff_check "content match tkn20+pqc" "$TC/plaintext.txt" "$TC/tkn20_pqc/recovered.txt"

# ================================================================
# 8. SETUP_BUFFER / GENKEY_BUFFER
# ================================================================
echo; echo "--- [8] Setup_Buffer / GenKey_Buffer ---"

# ---- ac17 ----
$EXEC setup_buffer --scheme ac17 2>/dev/null > "$TC/buf_ac17/setup.txt"
run "setup_buffer ac17" test -s "$TC/buf_ac17/setup.txt"
grep -A1 "PUBLIC KEY" "$TC/buf_ac17/setup.txt" | grep -v "PUBLIC KEY" | grep -v '^--$' > "$TC/buf_ac17/pk.key"
grep -A1 "MASTER SECRET KEY" "$TC/buf_ac17/setup.txt" | grep -v "MASTER SECRET KEY" | grep -v '^--$' > "$TC/buf_ac17/msk.key"
run "buf_msk_ac17 extracted" test -s "$TC/buf_ac17/msk.key"
run "genkey_buffer ac17"  $EXEC genkey_buffer --scheme ac17 "$TC/buf_ac17/msk.key" "A B C"

# ---- ac17+pqc ----
$EXEC setup_buffer --scheme ac17 --pqc 2>/dev/null > "$TC/buf_ac17_pqc/setup.txt"
run "setup_buffer ac17+pqc" test -s "$TC/buf_ac17_pqc/setup.txt"
grep -A1 "PUBLIC KEY" "$TC/buf_ac17_pqc/setup.txt" | head -n 2 | tail -n 1 > "$TC/buf_ac17_pqc/cpabe_pk.key"
grep -A1 "MASTER SECRET KEY" "$TC/buf_ac17_pqc/setup.txt" | tail -n 1 > "$TC/buf_ac17_pqc/cpabe_msk.key"
grep -A1 "PQC PUBLIC KEY" "$TC/buf_ac17_pqc/setup.txt" | tail -n 1 > "$TC/buf_ac17_pqc/pqc_pk.key"
grep -A1 "PQC SECRET KEY" "$TC/buf_ac17_pqc/setup.txt" | tail -n 1 > "$TC/buf_ac17_pqc/pqc_sk.key"
$EXEC genkey_buffer --scheme ac17 "$TC/buf_ac17_pqc/cpabe_msk.key" "A B C" 2>/dev/null > "$TC/buf_ac17_pqc/sk_raw.txt"
grep -A1 "SECRET KEY" "$TC/buf_ac17_pqc/sk_raw.txt" | tail -n 1 > "$TC/buf_ac17_pqc/sk.key"

# ---- tkn20 ----
$EXEC setup_buffer --scheme tkn20 2>/dev/null > "$TC/buf_tkn20/setup.txt"
run "setup_buffer tkn20" test -s "$TC/buf_tkn20/setup.txt"
grep -A1 "PUBLIC KEY" "$TC/buf_tkn20/setup.txt" | grep -v "PUBLIC KEY" | grep -v '^--$' > "$TC/buf_tkn20/pk.key"
grep -A1 "MASTER SECRET KEY" "$TC/buf_tkn20/setup.txt" | grep -v "MASTER SECRET KEY" | grep -v '^--$' > "$TC/buf_tkn20/msk.key"
run "buf_msk_tkn20 extracted" test -s "$TC/buf_tkn20/msk.key"
run "genkey_buffer tkn20" $EXEC genkey_buffer --scheme tkn20 "$TC/buf_tkn20/msk.key" "admin it"

# ---- tkn20+pqc ----
$EXEC setup_buffer --scheme tkn20 --pqc 2>/dev/null > "$TC/buf_tkn20_pqc/setup.txt"
run "setup_buffer tkn20+pqc" test -s "$TC/buf_tkn20_pqc/setup.txt"
grep -A1 "PUBLIC KEY" "$TC/buf_tkn20_pqc/setup.txt" | head -n 2 | tail -n 1 > "$TC/buf_tkn20_pqc/cpabe_pk.key"
grep -A1 "MASTER SECRET KEY" "$TC/buf_tkn20_pqc/setup.txt" | tail -n 1 > "$TC/buf_tkn20_pqc/cpabe_msk.key"
grep -A1 "PQC PUBLIC KEY" "$TC/buf_tkn20_pqc/setup.txt" | tail -n 1 > "$TC/buf_tkn20_pqc/pqc_pk.key"
grep -A1 "PQC SECRET KEY" "$TC/buf_tkn20_pqc/setup.txt" | tail -n 1 > "$TC/buf_tkn20_pqc/pqc_sk.key"
$EXEC genkey_buffer --scheme tkn20 "$TC/buf_tkn20_pqc/cpabe_msk.key" "admin it" 2>/dev/null > "$TC/buf_tkn20_pqc/sk_raw.txt"
grep -A1 "SECRET KEY" "$TC/buf_tkn20_pqc/sk_raw.txt" | tail -n 1 > "$TC/buf_tkn20_pqc/sk.key"

# ================================================================
# 9. ENCRYPT_BUFFER / DECRYPT_BUFFER  (file-based keys, all schemes)
# ================================================================
echo; echo "--- [9] EncryptBuffer/DecryptBuffer ac17 ---"
run "encrypt_buffer ac17" $EXEC encrypt_buffer --scheme ac17 "$TC/ac17/cpabe_pk.key" "Hello from buffer ac17!" "((A and C) or E)" "$TC/buf_ac17/ct.bin"
run_visible "decrypt_buffer ac17" $EXEC decrypt_buffer "$TC/ac17/sk.key" "$TC/buf_ac17/ct.bin"

echo; echo "--- [9] EncryptBuffer/DecryptBuffer tkn20 ---"
run "encrypt_buffer tkn20" $EXEC encrypt_buffer --scheme tkn20 "$TC/tkn20/cpabe_pk.key" "Hello from buffer tkn20!" "admin and it" "$TC/buf_tkn20/ct.bin"
run_visible "decrypt_buffer tkn20" $EXEC decrypt_buffer "$TC/tkn20/sk.key" "$TC/buf_tkn20/ct.bin"

# ================================================================
# 10. ENCRYPT_BUFFER+SIGN / DECRYPT_BUFFER+VERIFY
# ================================================================
echo; echo "--- [10] EncryptBuffer+Sign / DecryptBuffer+Verify ac17 ---"
run "encrypt_buffer ac17+pqc" $EXEC encrypt_buffer --scheme ac17 --pqc "$TC/buf_ac17_pqc/cpabe_pk.key" "$TC/buf_ac17_pqc/pqc_sk.key" "Hello signed buffer!" "((A and C) or E)" "$TC/buf_ac17_pqc/ct_pqc.bin"
run "decrypt_buffer ac17+pqc" $EXEC decrypt_buffer --pqc "$TC/buf_ac17_pqc/sk.key" "$TC/buf_ac17_pqc/pqc_pk.key" "$TC/buf_ac17_pqc/ct_pqc.bin"

echo; echo "--- [10] EncryptBuffer+Sign / DecryptBuffer+Verify tkn20 ---"
run "encrypt_buffer tkn20+pqc" $EXEC encrypt_buffer --scheme tkn20 --pqc "$TC/buf_tkn20_pqc/cpabe_pk.key" "$TC/buf_tkn20_pqc/pqc_sk.key" "Hello signed buffer tkn20!" "admin and it" "$TC/buf_tkn20_pqc/ct_pqc.bin"
run "decrypt_buffer tkn20+pqc" $EXEC decrypt_buffer --pqc "$TC/buf_tkn20_pqc/sk.key" "$TC/buf_tkn20_pqc/pqc_pk.key" "$TC/buf_tkn20_pqc/ct_pqc.bin"

# ================================================================
# SUMMARY
# ================================================================
echo
echo "================================================================"
echo " Results: $PASS PASSED  /  $FAIL FAILED"
echo "================================================================"
[ "$FAIL" -gt 0 ] && { echo " Some tests FAILED."; exit 1; } || { echo " All tests PASSED!"; exit 0; }