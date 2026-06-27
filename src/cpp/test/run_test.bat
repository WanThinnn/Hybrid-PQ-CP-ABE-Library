@echo off
setlocal EnableDelayedExpansion

set EXEC=build\main.exe
set TC=test_case
set PASS=0
set FAIL=0

echo ================================================================
echo  Hybrid CP-ABE Full Test Suite (Windows)
echo ================================================================

:: Create dedicated directories for each scheme
if not exist %TC% mkdir %TC%
if not exist %TC%\ac17 mkdir %TC%\ac17
if not exist %TC%\ac17_pqc mkdir %TC%\ac17_pqc
if not exist %TC%\tkn20 mkdir %TC%\tkn20
if not exist %TC%\tkn20_pqc mkdir %TC%\tkn20_pqc
if not exist %TC%\buf_ac17 mkdir %TC%\buf_ac17
if not exist %TC%\buf_ac17_pqc mkdir %TC%\buf_ac17_pqc
if not exist %TC%\buf_tkn20 mkdir %TC%\buf_tkn20
if not exist %TC%\buf_tkn20_pqc mkdir %TC%\buf_tkn20_pqc
echo This is a secret message for testing Hybrid CP-ABE!> %TC%\plaintext.txt

:: ================================================================
:: 1. VERSION / HELP
:: ================================================================
echo.
echo --- [1] Version / Help ---
%EXEC% version
call :check "version"
%EXEC% --version
call :check "--version"
%EXEC% help >nul 2>&1
call :check "help"

:: ================================================================
:: 2. SETUP (all variants)
:: ================================================================
echo.
echo --- [2] Setup ---
%EXEC% setup --scheme ac17  %TC%\ac17
call :check "setup ac17"
%EXEC% setup --scheme ac17  --pqc %TC%\ac17_pqc
call :check "setup ac17+pqc"
%EXEC% setup --scheme tkn20 %TC%\tkn20
call :check "setup tkn20"
%EXEC% setup --scheme tkn20 --pqc %TC%\tkn20_pqc
call :check "setup tkn20+pqc"

:: ================================================================
:: 3. GENKEY (file-based, all schemes)
:: ================================================================
echo.
echo --- [3] GenKey ---
%EXEC% genkey --scheme ac17  %TC%\ac17\cpabe_msk.key        "A B C"    %TC%\ac17\sk.key
call :check "genkey ac17"
%EXEC% genkey --scheme ac17  %TC%\ac17_pqc\cpabe_msk.key    "A B C"    %TC%\ac17_pqc\sk.key >nul 2>&1
%EXEC% genkey --scheme tkn20 %TC%\tkn20\cpabe_msk.key       "admin it" %TC%\tkn20\sk.key
call :check "genkey tkn20"
%EXEC% genkey --scheme tkn20 %TC%\tkn20_pqc\cpabe_msk.key   "admin it" %TC%\tkn20_pqc\sk.key >nul 2>&1

:: ================================================================
:: 4. ENCRYPT / DECRYPT  ac17
:: ================================================================
echo.
echo --- [4] Encrypt/Decrypt ac17 ---
%EXEC% encrypt --scheme ac17 %TC%\ac17\cpabe_pk.key %TC%\plaintext.txt "((A and C) or E)" %TC%\ac17\ct.bin
call :check "encrypt ac17"
%EXEC% decrypt %TC%\ac17\sk.key %TC%\ac17\ct.bin %TC%\ac17\recovered.txt
call :check "decrypt ac17"
fc /b %TC%\plaintext.txt %TC%\ac17\recovered.txt >nul 2>&1
call :check "content match ac17"

:: ================================================================
:: 5. ENCRYPT / DECRYPT  tkn20
:: ================================================================
echo.
echo --- [5] Encrypt/Decrypt tkn20 ---
%EXEC% encrypt --scheme tkn20 %TC%\tkn20\cpabe_pk.key %TC%\plaintext.txt "admin and it" %TC%\tkn20\ct.bin
call :check "encrypt tkn20"
%EXEC% decrypt %TC%\tkn20\sk.key %TC%\tkn20\ct.bin %TC%\tkn20\recovered.txt
call :check "decrypt tkn20"
fc /b %TC%\plaintext.txt %TC%\tkn20\recovered.txt >nul 2>&1
call :check "content match tkn20"

:: ================================================================
:: 6. ENCRYPT / DECRYPT  ac17 + PQC
:: ================================================================
echo.
echo --- [6] Encrypt/Decrypt ac17+PQC ---
%EXEC% encrypt --scheme ac17 --pqc %TC%\ac17_pqc\cpabe_pk.key %TC%\ac17_pqc\pqc_sk.key %TC%\plaintext.txt "((A and C) or E)" %TC%\ac17_pqc\ct.bin
call :check "encrypt ac17+pqc"
%EXEC% decrypt --pqc %TC%\ac17_pqc\sk.key %TC%\ac17_pqc\pqc_pk.key %TC%\ac17_pqc\ct.bin %TC%\ac17_pqc\recovered.txt
call :check "decrypt ac17+pqc"
fc /b %TC%\plaintext.txt %TC%\ac17_pqc\recovered.txt >nul 2>&1
call :check "content match ac17+pqc"

:: ================================================================
:: 7. ENCRYPT / DECRYPT  tkn20 + PQC
:: ================================================================
echo.
echo --- [7] Encrypt/Decrypt tkn20+PQC ---
%EXEC% encrypt --scheme tkn20 --pqc %TC%\tkn20_pqc\cpabe_pk.key %TC%\tkn20_pqc\pqc_sk.key %TC%\plaintext.txt "admin and it" %TC%\tkn20_pqc\ct.bin
call :check "encrypt tkn20+pqc"
%EXEC% decrypt --pqc %TC%\tkn20_pqc\sk.key %TC%\tkn20_pqc\pqc_pk.key %TC%\tkn20_pqc\ct.bin %TC%\tkn20_pqc\recovered.txt
call :check "decrypt tkn20+pqc"
fc /b %TC%\plaintext.txt %TC%\tkn20_pqc\recovered.txt >nul 2>&1
call :check "content match tkn20+pqc"

:: ================================================================
:: 8. SETUP_BUFFER / GENKEY_BUFFER
:: ================================================================
echo.
echo --- [8] Setup_Buffer / GenKey_Buffer ---

:: ---- ac17 ----
%EXEC% setup_buffer --scheme ac17 > %TC%\buf_ac17\setup.txt 2>&1
if exist %TC%\buf_ac17\setup.txt (
    echo   [PASS] setup_buffer ac17
    set /a PASS+=1
) else (
    echo   [FAIL] setup_buffer ac17
    set /a FAIL+=1
)
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf_ac17\setup.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'PUBLIC KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_ac17\pk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'MASTER SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_ac17\msk.key' -NoNewline }" ^
    "}" >nul 2>&1
%EXEC% genkey_buffer --scheme ac17 %TC%\buf_ac17\msk.key "A B C" >nul 2>&1
call :check "genkey_buffer ac17"

:: ---- ac17+pqc ----
%EXEC% setup_buffer --scheme ac17 --pqc > %TC%\buf_ac17_pqc\setup.txt 2>&1
if exist %TC%\buf_ac17_pqc\setup.txt (
    echo   [PASS] setup_buffer ac17+pqc
    set /a PASS+=1
) else (
    echo   [FAIL] setup_buffer ac17+pqc
    set /a FAIL+=1
)
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf_ac17_pqc\setup.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'PUBLIC KEY' -and -not ($lines[$i] -match 'PQC') -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_ac17_pqc\cpabe_pk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'MASTER SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_ac17_pqc\cpabe_msk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'PQC PUBLIC KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_ac17_pqc\pqc_pk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'PQC SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_ac17_pqc\pqc_sk.key' -NoNewline }" ^
    "}" >nul 2>&1
%EXEC% genkey_buffer --scheme ac17 %TC%\buf_ac17_pqc\cpabe_msk.key "A B C" > %TC%\buf_ac17_pqc\sk_raw.txt 2>&1
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf_ac17_pqc\sk_raw.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_ac17_pqc\sk.key' -NoNewline }" ^
    "}" >nul 2>&1


:: ---- tkn20 ----
%EXEC% setup_buffer --scheme tkn20 > %TC%\buf_tkn20\setup.txt 2>&1
if exist %TC%\buf_tkn20\setup.txt (
    echo   [PASS] setup_buffer tkn20
    set /a PASS+=1
) else (
    echo   [FAIL] setup_buffer tkn20
    set /a FAIL+=1
)
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf_tkn20\setup.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'PUBLIC KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_tkn20\pk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'MASTER SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_tkn20\msk.key' -NoNewline }" ^
    "}" >nul 2>&1
%EXEC% genkey_buffer --scheme tkn20 %TC%\buf_tkn20\msk.key "admin it" >nul 2>&1
call :check "genkey_buffer tkn20"

:: ---- tkn20+pqc ----
%EXEC% setup_buffer --scheme tkn20 --pqc > %TC%\buf_tkn20_pqc\setup.txt 2>&1
if exist %TC%\buf_tkn20_pqc\setup.txt (
    echo   [PASS] setup_buffer tkn20+pqc
    set /a PASS+=1
) else (
    echo   [FAIL] setup_buffer tkn20+pqc
    set /a FAIL+=1
)
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf_tkn20_pqc\setup.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'PUBLIC KEY' -and -not ($lines[$i] -match 'PQC') -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_tkn20_pqc\cpabe_pk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'MASTER SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_tkn20_pqc\cpabe_msk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'PQC PUBLIC KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_tkn20_pqc\pqc_pk.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'PQC SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_tkn20_pqc\pqc_sk.key' -NoNewline }" ^
    "}" >nul 2>&1
%EXEC% genkey_buffer --scheme tkn20 %TC%\buf_tkn20_pqc\cpabe_msk.key "admin it" > %TC%\buf_tkn20_pqc\sk_raw.txt 2>&1
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf_tkn20_pqc\sk_raw.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf_tkn20_pqc\sk.key' -NoNewline }" ^
    "}" >nul 2>&1


:: ================================================================
:: 9. ENCRYPT_BUFFER / DECRYPT_BUFFER  (all schemes)
:: ================================================================
echo.
echo --- [9] EncryptBuffer/DecryptBuffer ac17 ---
%EXEC% encrypt_buffer --scheme ac17 %TC%\ac17\cpabe_pk.key "Hello from buffer ac17!" "((A and C) or E)" %TC%\buf_ac17\ct.bin
call :check "encrypt_buffer ac17"
%EXEC% decrypt_buffer %TC%\ac17\sk.key %TC%\buf_ac17\ct.bin
call :check "decrypt_buffer ac17"

echo.
echo --- [9] EncryptBuffer/DecryptBuffer tkn20 ---
%EXEC% encrypt_buffer --scheme tkn20 %TC%\tkn20\cpabe_pk.key "Hello from buffer tkn20!" "admin and it" %TC%\buf_tkn20\ct.bin
call :check "encrypt_buffer tkn20"
%EXEC% decrypt_buffer %TC%\tkn20\sk.key %TC%\buf_tkn20\ct.bin
call :check "decrypt_buffer tkn20"

:: ================================================================
:: 10. ENCRYPT_BUFFER+SIGN / DECRYPT_BUFFER+VERIFY
:: ================================================================
echo.
echo --- [10] EncryptBuffer+Sign / DecryptBuffer+Verify ac17 ---
%EXEC% encrypt_buffer --scheme ac17 --pqc %TC%\buf_ac17_pqc\cpabe_pk.key %TC%\buf_ac17_pqc\pqc_sk.key "Hello signed buffer!" "((A and C) or E)" %TC%\buf_ac17_pqc\ct_pqc.bin
call :check "encrypt_buffer ac17+pqc"
%EXEC% decrypt_buffer --pqc %TC%\buf_ac17_pqc\sk.key %TC%\buf_ac17_pqc\pqc_pk.key %TC%\buf_ac17_pqc\ct_pqc.bin
call :check "decrypt_buffer ac17+pqc"

echo.
echo --- [10] EncryptBuffer+Sign / DecryptBuffer+Verify tkn20 ---
%EXEC% encrypt_buffer --scheme tkn20 --pqc %TC%\buf_tkn20_pqc\cpabe_pk.key %TC%\buf_tkn20_pqc\pqc_sk.key "Hello signed buffer tkn20!" "admin and it" %TC%\buf_tkn20_pqc\ct_pqc.bin
call :check "encrypt_buffer tkn20+pqc"
%EXEC% decrypt_buffer --pqc %TC%\buf_tkn20_pqc\sk.key %TC%\buf_tkn20_pqc\pqc_pk.key %TC%\buf_tkn20_pqc\ct_pqc.bin
call :check "decrypt_buffer tkn20+pqc"

:: ================================================================
:: SUMMARY
:: ================================================================
echo.
echo ================================================================
echo  Results: !PASS! PASSED  /  !FAIL! FAILED
echo ================================================================
if !FAIL! GTR 0 (
    echo  Some tests FAILED.
    exit /b 1
) else (
    echo  All tests PASSED!
    exit /b 0
)

:check
if %ERRORLEVEL% EQU 0 (
    echo   [PASS] %~1
    set /a PASS+=1
) else (
    echo   [FAIL] %~1 ^(exit %ERRORLEVEL%^)
    set /a FAIL+=1
)
goto :eof