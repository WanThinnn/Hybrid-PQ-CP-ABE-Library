@echo off
cd /d "%~dp0..\.."
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b 1
for %%H in (cpabe-scheme.h hybrid-pq-cp-abe.h) do (
  for %%D in (/DHEADER_CHECK_STATIC /DBUILD_DLL /DUSE_DLL) do (
    cl.exe /nologo /MD /W4 /WX /Zs /TC /Iinclude /DHEADER_FILE=\"hybrid_pq_cp_abe/%%H\" %%D tests\cpp\header_checks\public_headers.c
    if errorlevel 1 exit /b 1
    cl.exe /nologo /MD /EHsc /W4 /WX /Zs /TP /Iinclude /DHEADER_FILE=\"hybrid_pq_cp_abe/%%H\" %%D tests\cpp\header_checks\public_headers.cpp
    if errorlevel 1 exit /b 1
  )
)
echo PASS: Both public headers compile as C and C++ with static, DLL export and DLL import defines.
