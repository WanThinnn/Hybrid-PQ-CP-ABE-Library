@echo off
setlocal EnableDelayedExpansion

set EXEC=build\main.exe
set TC=test_case
set PASS=0
set FAIL=0

echo ================================================================
echo  Hybrid CP-ABE Full Test Suite (Windows)
echo ================================================================

if not exist %TC% mkdir %TC%
if not exist %TC%\tkn20 mkdir %TC%\tkn20
if not exist %TC%\pqc mkdir %TC%\pqc
if not exist %TC%\pqc_tkn20 mkdir %TC%\pqc_tkn20
if not exist %TC%\buf mkdir %TC%\buf
echo This is a secret message for testing Hybrid CP-ABE!> %TC%\plaintext.txt

:: ================================================================
:: 1. VERSION / HELP
:: ================================================================
echo.
echo --- [1] Version / Help ---
%EXEC% version & call :check "version"
%EXEC% --version & call :check "--version"
%EXEC% help >nul 2>&1 & call :check "help"

:: ================================================================
:: 2. SETUP (all variants)
::   ac17      -> test_case\cpabe_msk.key + cpabe_pk.key
::   tkn20     -> test_case\tkn20\cpabe_msk.key + cpabe_pk.key
::   ac17+pqc  -> test_case\pqc\cpabe_msk.key + pqc_sk.key + pqc_pk.key
::   tkn20+pqc -> test_case\pqc_tkn20\cpabe_msk.key + pqc_sk.key + pqc_pk.key
:: ================================================================
echo.
echo --- [2] Setup ---
%EXEC% setup --scheme ac17  %TC%
call :check "setup ac17"
%EXEC% setup --scheme tkn20 %TC%\tkn20
call :check "setup tkn20"
%EXEC% setup --scheme ac17  --pqc %TC%\pqc
call :check "setup ac17+pqc"
%EXEC% setup --scheme tkn20 --pqc %TC%\pqc_tkn20
call :check "setup tkn20+pqc"

:: ================================================================
:: 3. GENKEY (file-based, all schemes)
:: ================================================================
echo.
echo --- [3] GenKey ---
%EXEC% genkey --scheme ac17  %TC%\cpabe_msk.key            "A B C"    %TC%\sk_ac17.key
call :check "genkey ac17"
%EXEC% genkey --scheme tkn20 %TC%\tkn20\cpabe_msk.key      "admin it" %TC%\tkn20\sk_tkn20.key
call :check "genkey tkn20"
:: Keys for PQC decrypt
%EXEC% genkey --scheme ac17  %TC%\pqc\cpabe_msk.key        "A B C"    %TC%\pqc\sk_ac17.key       >nul 2>&1
%EXEC% genkey --scheme tkn20 %TC%\pqc_tkn20\cpabe_msk.key  "admin it" %TC%\pqc_tkn20\sk_tkn20.key >nul 2>&1

:: ================================================================
:: 4. ENCRYPT / DECRYPT  ac17
:: ================================================================
echo.
echo --- [4] Encrypt/Decrypt ac17 ---
%EXEC% encrypt --scheme ac17 %TC%\cpabe_pk.key %TC%\plaintext.txt "((A and C) or E)" %TC%\ct_ac17.bin
call :check "encrypt ac17"
%EXEC% decrypt %TC%\sk_ac17.key %TC%\ct_ac17.bin %TC%\recovered_ac17.txt
call :check "decrypt ac17"
fc /b %TC%\plaintext.txt %TC%\recovered_ac17.txt >nul 2>&1
call :check "content match ac17"

:: ================================================================
:: 5. ENCRYPT / DECRYPT  tkn20
:: ================================================================
echo.
echo --- [5] Encrypt/Decrypt tkn20 ---
%EXEC% encrypt --scheme tkn20 %TC%\tkn20\cpabe_pk.key %TC%\plaintext.txt "admin and it" %TC%\ct_tkn20.bin
call :check "encrypt tkn20"
%EXEC% decrypt %TC%\tkn20\sk_tkn20.key %TC%\ct_tkn20.bin %TC%\recovered_tkn20.txt
call :check "decrypt tkn20"
fc /b %TC%\plaintext.txt %TC%\recovered_tkn20.txt >nul 2>&1
call :check "content match tkn20"

:: ================================================================
:: 6. ENCRYPT / DECRYPT  ac17 + PQC
:: ================================================================
echo.
echo --- [6] Encrypt/Decrypt ac17+PQC ---
%EXEC% encrypt --scheme ac17 --pqc %TC%\pqc\cpabe_pk.key %TC%\pqc\pqc_sk.key %TC%\plaintext.txt "((A and C) or E)" %TC%\ct_pqc_ac17.bin
call :check "encrypt ac17+pqc"
%EXEC% decrypt --pqc %TC%\pqc\sk_ac17.key %TC%\pqc\pqc_pk.key %TC%\ct_pqc_ac17.bin %TC%\recovered_pqc_ac17.txt
call :check "decrypt ac17+pqc"
fc /b %TC%\plaintext.txt %TC%\recovered_pqc_ac17.txt >nul 2>&1
call :check "content match ac17+pqc"

:: ================================================================
:: 7. ENCRYPT / DECRYPT  tkn20 + PQC
:: ================================================================
echo.
echo --- [7] Encrypt/Decrypt tkn20+PQC ---
%EXEC% encrypt --scheme tkn20 --pqc %TC%\pqc_tkn20\cpabe_pk.key %TC%\pqc_tkn20\pqc_sk.key %TC%\plaintext.txt "admin and it" %TC%\ct_pqc_tkn20.bin
call :check "encrypt tkn20+pqc"
%EXEC% decrypt --pqc %TC%\pqc_tkn20\sk_tkn20.key %TC%\pqc_tkn20\pqc_pk.key %TC%\ct_pqc_tkn20.bin %TC%\recovered_pqc_tkn20.txt
call :check "decrypt tkn20+pqc"
fc /b %TC%\plaintext.txt %TC%\recovered_pqc_tkn20.txt >nul 2>&1
call :check "content match tkn20+pqc"

:: ================================================================
:: 8. SETUP_BUFFER / GENKEY_BUFFER
::
:: Flow: main.cpp reads file -> Base64Decoder -> passes to genkeyBuffer
::       genkeyBuffer: decodeBase64(input) -> JSON -> rabe_from_json()
:: So file must contain Base64(JSON) -- exactly what setup_buffer prints.
:: Run setup_buffer ONCE, save to file, parse PK+MSK lines from that file.
:: ================================================================
echo.
echo --- [8] Setup_Buffer / GenKey_Buffer ---

:: ---- ac17 ----
%EXEC% setup_buffer --scheme ac17 > %TC%\buf\setup_ac17.txt 2>&1
if exist %TC%\buf\setup_ac17.txt (
    echo   [PASS] setup_buffer ac17 & set /a PASS+=1
) else (
    echo   [FAIL] setup_buffer ac17 & set /a FAIL+=1
)
:: Parse PK (line after "PUBLIC KEY") and MSK (line after "MASTER SECRET KEY")
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf\setup_ac17.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'PUBLIC KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf\pk_ac17.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'MASTER SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf\msk_ac17.key' -NoNewline }" ^
    "}" >nul 2>&1

%EXEC% genkey_buffer --scheme ac17 %TC%\buf\msk_ac17.key "A B C" >nul 2>&1
call :check "genkey_buffer ac17"

:: ---- tkn20 ----
%EXEC% setup_buffer --scheme tkn20 > %TC%\buf\setup_tkn20.txt 2>&1
if exist %TC%\buf\setup_tkn20.txt (
    echo   [PASS] setup_buffer tkn20 & set /a PASS+=1
) else (
    echo   [FAIL] setup_buffer tkn20 & set /a FAIL+=1
)
powershell -NoProfile -Command ^
    "$lines = Get-Content '%TC%\buf\setup_tkn20.txt';" ^
    "for ($i=0; $i -lt $lines.Count; $i++) {" ^
    "  if ($lines[$i] -match 'PUBLIC KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf\pk_tkn20.key' -NoNewline }" ^
    "  if ($lines[$i] -match 'MASTER SECRET KEY' -and $i+1 -lt $lines.Count) { $lines[$i+1] | Set-Content '%TC%\buf\msk_tkn20.key' -NoNewline }" ^
    "}" >nul 2>&1

%EXEC% genkey_buffer --scheme tkn20 %TC%\buf\msk_tkn20.key "admin it" >nul 2>&1
call :check "genkey_buffer tkn20"

:: ================================================================
:: 9. ENCRYPT_BUFFER / DECRYPT_BUFFER  (all schemes)
:: ================================================================
echo.
echo --- [9] EncryptBuffer/DecryptBuffer ac17 ---
%EXEC% encrypt_buffer --scheme ac17 %TC%\cpabe_pk.key "Hello from buffer ac17!" "((A and C) or E)" %TC%\ct_buf_ac17.bin
call :check "encrypt_buffer ac17"
%EXEC% decrypt_buffer %TC%\sk_ac17.key %TC%\ct_buf_ac17.bin
call :check "decrypt_buffer ac17"

echo.
echo --- [9] EncryptBuffer/DecryptBuffer tkn20 ---
%EXEC% encrypt_buffer --scheme tkn20 %TC%\tkn20\cpabe_pk.key "Hello from buffer tkn20!" "admin and it" %TC%\ct_buf_tkn20.bin
call :check "encrypt_buffer tkn20"
%EXEC% decrypt_buffer %TC%\tkn20\sk_tkn20.key %TC%\ct_buf_tkn20.bin
call :check "decrypt_buffer tkn20"

:: ================================================================
:: 10. ENCRYPT_BUFFER+SIGN / DECRYPT_BUFFER+VERIFY
:: ================================================================
echo.
echo --- [10] EncryptBuffer+Sign / DecryptBuffer+Verify ac17 ---
%EXEC% encrypt_buffer --scheme ac17 --pqc %TC%\cpabe_pk.key %TC%\pqc\pqc_sk.key "Hello signed buffer!" "((A and C) or E)" %TC%\ct_buf_pqc_ac17.bin
call :check "encrypt_buffer ac17+pqc"
%EXEC% decrypt_buffer --pqc %TC%\pqc\sk_ac17.key %TC%\pqc\pqc_pk.key %TC%\ct_buf_pqc_ac17.bin
call :check "decrypt_buffer ac17+pqc"

echo.
echo --- [10] EncryptBuffer+Sign / DecryptBuffer+Verify tkn20 ---
%EXEC% encrypt_buffer --scheme tkn20 --pqc %TC%\tkn20\cpabe_pk.key %TC%\pqc_tkn20\pqc_sk.key "Hello signed buffer tkn20!" "admin and it" %TC%\ct_buf_pqc_tkn20.bin
call :check "encrypt_buffer tkn20+pqc"
%EXEC% decrypt_buffer --pqc %TC%\pqc_tkn20\sk_tkn20.key %TC%\pqc_tkn20\pqc_pk.key %TC%\ct_buf_pqc_tkn20.bin
call :check "decrypt_buffer tkn20+pqc"

:: ================================================================
:: SUMMARY
:: ================================================================
echo.
echo ================================================================
echo  Results: !PASS! PASSED  /  !FAIL! FAILED
echo ================================================================
if !FAIL! GTR 0 (echo  Some tests FAILED. & exit /b 1) else (echo  All tests PASSED! & exit /b 0)

:check
if %ERRORLEVEL% EQU 0 (
    echo   [PASS] %~1 & set /a PASS+=1
) else (
    echo   [FAIL] %~1  ^(exit %ERRORLEVEL%^) & set /a FAIL+=1
)
goto :eof