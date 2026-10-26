Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

$DepsDir = Join-Path $Root "build\deps\windows"
$StageDir = Join-Path $DepsDir "stage"
$IncludeDir = Join-Path $DepsDir "include"
$TempDir = Join-Path $DepsDir "tmp"
$Stamp = Join-Path $DepsDir ".ready"

New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
$env:TEMP = $TempDir
$env:TMP = $TempDir
$env:TMPDIR = $TempDir

$Required = @("cmake", "msbuild", "cargo", "go", "gcc", "lib.exe")
foreach ($Tool in $Required) {
    if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) {
        throw "Missing required tool: $Tool"
    }
}

New-Item -ItemType Directory -Force -Path $DepsDir, $StageDir, (Join-Path $IncludeDir "rabe"), "lib\static", "lib\dynamic", "bindings\tkn20\include" | Out-Null

$Expected = @(
    "lib\static\libcryptopp.lib",
    "lib\static\liboqs.lib",
    "lib\static\librabe_ffi.lib",
    "lib\dynamic\libcpabe_tkn20.dll"
)
if ((Test-Path $Stamp) -and (($Expected | Where-Object { -not (Test-Path $_) }).Count -eq 0)) {
    Write-Host "Dependencies already built for Windows. Use 'make deps-clean' to force a rebuild."
    exit 0
}

Write-Host "==> Crypto++"
& msbuild "vendor\cryptopp\cryptlib.vcxproj" /m /p:Configuration=Release /p:Platform=x64
if ($LASTEXITCODE -ne 0) { throw "Crypto++ build failed" }
$CryptoLib = Get-ChildItem "vendor\cryptopp" -Recurse -Filter "cryptlib.lib" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $CryptoLib) { throw "cryptlib.lib not found after Crypto++ build" }
Copy-Item $CryptoLib.FullName "lib\static\libcryptopp.lib" -Force

Write-Host "==> liboqs"
$OqsBuild = Join-Path $DepsDir "liboqs"
& cmake -S "vendor\liboqs" -B $OqsBuild -G "Visual Studio 17 2022" -A x64 "-DCMAKE_INSTALL_PREFIX=$StageDir" "-DBUILD_SHARED_LIBS=OFF" "-DOQS_BUILD_ONLY_LIB=ON" "-DOQS_USE_OPENSSL=OFF" "-DOQS_ALGS_ENABLED=STD"
if ($LASTEXITCODE -ne 0) { throw "liboqs configure failed" }
& cmake --build $OqsBuild --config Release --target install
if ($LASTEXITCODE -ne 0) { throw "liboqs build failed" }
$OqsLib = Get-ChildItem $StageDir -Recurse -Filter "oqs.lib" | Select-Object -First 1
if (-not $OqsLib) { throw "oqs.lib not found after liboqs build" }
Copy-Item $OqsLib.FullName "lib\static\liboqs.lib" -Force
$OqsInclude = Join-Path $StageDir "include\oqs"
if (Test-Path (Join-Path $IncludeDir "oqs")) { Remove-Item (Join-Path $IncludeDir "oqs") -Recurse -Force }
Copy-Item $OqsInclude (Join-Path $IncludeDir "oqs") -Recurse -Force

Write-Host "==> librabe-ffi"
$env:CARGO_TARGET_DIR = Join-Path $DepsDir "rabe-target"
& cargo build --locked --manifest-path "vendor\librabe-ffi\Cargo.toml" --release
if ($LASTEXITCODE -ne 0) { throw "librabe-ffi build failed" }
$RabeRelease = Join-Path $env:CARGO_TARGET_DIR "release"
$RabeStatic = Get-ChildItem $RabeRelease -Filter "rabe_ffi.lib" | Select-Object -First 1
if (-not $RabeStatic) { throw "rabe_ffi.lib not found after Cargo build" }
Copy-Item $RabeStatic.FullName "lib\static\librabe_ffi.lib" -Force
$RabeDll = Get-ChildItem $RabeRelease -Filter "rabe_ffi.dll" | Select-Object -First 1
if ($RabeDll) { Copy-Item $RabeDll.FullName "lib\dynamic\librabe_ffi.dll" -Force }
Copy-Item "vendor\librabe-ffi\rabe.h" (Join-Path $IncludeDir "rabe\rabe.h") -Force

Write-Host "==> CIRCL/TKN20 C bridge"
$TknDir = Join-Path $DepsDir "tkn20"
New-Item -ItemType Directory -Force -Path $TknDir | Out-Null
Push-Location "bindings\tkn20"
try {
    $env:CGO_ENABLED = "1"
    & go build -buildmode=c-shared -o (Join-Path $TknDir "libcpabe_tkn20.dll") .
    if ($LASTEXITCODE -ne 0) { throw "TKN20 Go bridge build failed" }
} finally {
    Pop-Location
}
Copy-Item (Join-Path $TknDir "libcpabe_tkn20.dll") "lib\dynamic\libcpabe_tkn20.dll" -Force
Copy-Item (Join-Path $TknDir "libcpabe_tkn20.h") "bindings\tkn20\include\cpabe_tkn20.h" -Force
Copy-Item "bindings\tkn20\libcpabe_tkn20.def" "lib\static\libcpabe_tkn20.def" -Force
& lib.exe /NOLOGO "/DEF:lib\static\libcpabe_tkn20.def" "/OUT:lib\static\libcpabe_tkn20.lib" /MACHINE:X64
if ($LASTEXITCODE -ne 0) { throw "TKN20 MSVC import library generation failed" }

@(
    "platform=windows",
    "cryptopp=5873a73a231c95771f5bbf3466a484952fb22780",
    "liboqs=e1f480f382d9443c4412133b55948374c77a5c21",
    "librabe-ffi=ff828d13a635042c9569cfb29117f299b553f946",
    "circl=901199c7d4fcefc8c43e8ad46397439ccd3a0ed0"
) | Set-Content $Stamp

Write-Host "Dependencies built successfully for Windows."
