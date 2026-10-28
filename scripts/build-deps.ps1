param(
    [ValidateSet("all", "cryptopp", "liboqs", "rabe", "tkn20")]
    [string]$Dependency = "all",
    [int]$Jobs = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

$DepsDir = Join-Path $Root "build\deps\windows"
$WorkDir = Join-Path $DepsDir ".work"
$IncludeDir = Join-Path $DepsDir "include"
$LibDir = Join-Path $DepsDir "lib"
$BuildVersion = "6"

$TotalJobs = $Jobs
if ($TotalJobs -le 0 -and $env:JOBS -match '^\d+$') {
    $TotalJobs = [int]$env:JOBS
} elseif ($TotalJobs -le 0 -and $env:MAKEFLAGS -match '(?:^|\s)-?j\s*(\d+)(?:\s|$)') {
    $TotalJobs = [int]$Matches[1]
} elseif ($TotalJobs -le 0 -and $env:MAKEFLAGS -match '--jobs(?:=|\s+)(\d+)') {
    $TotalJobs = [int]$Matches[1]
}
if ($TotalJobs -le 0) {
    $TotalJobs = [Environment]::ProcessorCount
}
if ($TotalJobs -le 0) {
    throw "Invalid job count: $TotalJobs"
}

Remove-Item Env:MAKEFLAGS -ErrorAction SilentlyContinue
Remove-Item Env:MFLAGS -ErrorAction SilentlyContinue
Remove-Item Env:MAKELEVEL -ErrorAction SilentlyContinue

$InnerJobs = $TotalJobs

Write-Host "Dependency build starting: windows (total jobs=$TotalJobs)"

New-Item -ItemType Directory -Force -Path $WorkDir, $IncludeDir, $LibDir | Out-Null

$Required = @("cmake", "msbuild", "cargo", "go", "gcc", "lib.exe", "cl.exe")
foreach ($Tool in $Required) {
    if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) {
        throw "Missing required tool: $Tool"
    }
}

function Get-TextHash([string]$Text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-FileDigest([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant()
}

function Get-FingerprintPath([string]$Name) {
    return Join-Path (Join-Path $LibDir $Name) ".fingerprint"
}

function Test-DependencyCache([string]$Name, [string]$Fingerprint, [string[]]$Outputs) {
    $FingerprintPath = Get-FingerprintPath $Name
    if (-not (Test-Path $FingerprintPath)) { return $false }
    if (-not (Select-String -Path $FingerprintPath -SimpleMatch "fingerprint=$Fingerprint" -Quiet)) { return $false }

    foreach ($Output in $Outputs) {
        if (-not (Test-Path $Output)) { return $false }
    }
    return $true
}

function Write-DependencyFingerprint([string]$Name, [string]$Fingerprint, [string[]]$Extra = @()) {
    $DepLibDir = Join-Path $LibDir $Name
    New-Item -ItemType Directory -Force -Path $DepLibDir | Out-Null

    @(
        "fingerprint=$Fingerprint",
        "platform=windows",
        "abi=msvc",
        "build_version=$BuildVersion"
    ) + $Extra | Set-Content (Get-FingerprintPath $Name)
}

function Get-Sccache {
    $Command = Get-Command sccache -ErrorAction SilentlyContinue
    if ($Command) { return $Command.Source }
    return $null
}

function Build-CryptoPP {
    Build-CryptoPPStatic
    Build-CryptoPPDll
}

function Build-CryptoPPStatic {
    $Upstream = Get-FileDigest "vendor\cryptopp\UPSTREAM.md"
    $Toolchain = (Get-Command cl.exe).Source
    $RuntimeProps = Join-Path $PSScriptRoot "cryptopp-msvc.props"
    $RuntimePropsHash = Get-FileDigest $RuntimeProps
    $Fingerprint = Get-TextHash "cryptopp|$BuildVersion|windows|$Upstream|$Toolchain|Release|x64|MSVC|out-of-source|$RuntimePropsHash"

    $DepLibDir = Join-Path $LibDir "cryptopp"
    $DepIncludeDir = Join-Path $IncludeDir "cryptopp"
    $Work = Join-Path $WorkDir "cryptopp"
    $OutDir = Join-Path $Work "out"
    $ObjDir = Join-Path $Work "obj"
    $CryptoLib = Join-Path $DepLibDir "libcryptopp.lib"
    $CryptoHeader = Join-Path $DepIncludeDir "aes.h"

    if (Test-DependencyCache "cryptopp" $Fingerprint @($CryptoLib, $CryptoHeader)) {
        Write-Host "==> Crypto++: cached"
        return
    }

    Write-Host "==> Crypto++ ($InnerJobs jobs, MSVC)"
    Remove-Item $Work, $DepLibDir, $DepIncludeDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $OutDir, $ObjDir, $DepLibDir, $DepIncludeDir | Out-Null

    $MsbuildOut = $OutDir.TrimEnd('\') + "\"
    $MsbuildObj = $ObjDir.TrimEnd('\') + "\"

    & msbuild "vendor\cryptopp\cryptlib.vcxproj" "/m:$InnerJobs" /p:Configuration=Release /p:Platform=x64 "/p:OutDir=$MsbuildOut" "/p:IntDir=$MsbuildObj" "/p:ForceImportBeforeCppTargets=$RuntimeProps"
    if ($LASTEXITCODE -ne 0) { throw "Crypto++ build failed" }

    $Built = Join-Path $OutDir "cryptlib.lib"
    if (-not (Test-Path $Built)) { throw "cryptlib.lib not found after Crypto++ build: $Built" }

    Copy-Item $Built $CryptoLib -Force
    Get-ChildItem "vendor\cryptopp" -Filter "*.h" | Copy-Item -Destination $DepIncludeDir -Force

    Write-DependencyFingerprint "cryptopp" $Fingerprint
    Remove-Item $Work -Recurse -Force
}

function Build-CryptoPPDll {
    $DllProps = Join-Path $PSScriptRoot "cryptopp-dll.props"
    $RuntimePropsHash = Get-FileDigest (Join-Path $PSScriptRoot "cryptopp-msvc.props")
    $DllPropsHash = Get-FileDigest $DllProps
    $SelfTestHash = Get-FileDigest "vendor\cryptopp\fipstest.cpp"
    $DllSourceHash = Get-FileDigest "vendor\cryptopp\dll.cpp"
    $Upstream = Get-FileDigest "vendor\cryptopp\UPSTREAM.md"
    $Toolchain = (Get-Command cl.exe).Source
    $Fingerprint = Get-TextHash "cryptopp-dll|$BuildVersion|$Upstream|$Toolchain|x64|Release|MD|$RuntimePropsHash|$DllPropsHash|$SelfTestHash|$DllSourceHash"
    $DepLibDir = Join-Path $LibDir "cryptopp"
    $Dll = Join-Path $DepLibDir "cryptopp.dll"
    $ImportLib = Join-Path $DepLibDir "cryptopp.lib"
    $FingerprintPath = Join-Path $DepLibDir ".dll-fingerprint"
    if ((Test-Path $Dll) -and (Test-Path $ImportLib) -and (Test-Path $FingerprintPath)) {
        if (Select-String -Path $FingerprintPath -SimpleMatch "fingerprint=$Fingerprint" -Quiet) {
            Write-Host "==> Crypto++ DLL: cached"
            return
        }
    }
    $Work = Join-Path $WorkDir "cryptopp-dll"
    $OutDir = Join-Path $Work "out"
    $ObjDir = Join-Path $Work "obj"
    New-Item -ItemType Directory -Force -Path $OutDir, $ObjDir | Out-Null
    Write-Host "==> Crypto++ DLL ($InnerJobs jobs, MSVC x64, /MD)"
    & msbuild "vendor\cryptopp\cryptdll.vcxproj" "/m:$InnerJobs" /p:Configuration=Release /p:Platform=x64 "/p:OutDir=$OutDir\" "/p:IntDir=$ObjDir\" "/p:ForceImportBeforeCppTargets=$DllProps"
    if ($LASTEXITCODE -ne 0) { throw "Crypto++ DLL build failed" }
    Copy-Item (Join-Path $OutDir "cryptopp.dll") $Dll -Force
    Copy-Item (Join-Path $OutDir "cryptopp.lib") $ImportLib -Force
    "fingerprint=$Fingerprint" | Set-Content $FingerprintPath
    Remove-Item $Work -Recurse -Force
    Write-Host "Crypto++ DLL: $Dll"
    Write-Host "Import library: $ImportLib"
}

function Build-LibOqs {
    $Upstream = Get-FileDigest "vendor\liboqs\UPSTREAM.md"
    $Toolchain = (Get-Command cl.exe).Source
    $Ninja = Get-Command ninja -ErrorAction SilentlyContinue
    $Generator = if ($Ninja) { "Ninja" } else { "Visual Studio 17 2022" }
    $CompilerOptsHash = Get-FileDigest "vendor\liboqs\.CMake\compiler_opts.cmake"
    $CMakeHash = Get-FileDigest "vendor\liboqs\CMakeLists.txt"
    $CommonHeaderHash = Get-FileDigest "vendor\liboqs\src\common\common.h"
    $Fingerprint = Get-TextHash "liboqs|$BuildVersion|windows|$Upstream|$Toolchain|$Generator|ML-KEM+ML-DSA|minimal|static+shared|PIC|no-openssl|MD|$CompilerOptsHash|$CMakeHash|$CommonHeaderHash"

    $DepLibDir = Join-Path $LibDir "liboqs"
    $DepIncludeDir = Join-Path $IncludeDir "liboqs"
    $WorkStatic = Join-Path $WorkDir "liboqs-static"
    $WorkShared = Join-Path $WorkDir "liboqs-shared"
    $StageStatic = Join-Path $WorkDir "liboqs-stage-static"
    $StageShared = Join-Path $WorkDir "liboqs-stage-shared"
    $OutStaticLib = Join-Path $DepLibDir "liboqs.lib"
    $OutDll = Join-Path $DepLibDir "liboqs.dll"
    $OutImportLib = Join-Path $DepLibDir "liboqs_import.lib"
    $OqsHeader = Join-Path $DepIncludeDir "oqs\oqs.h"

    if (Test-DependencyCache "liboqs" $Fingerprint @($OutStaticLib, $OutDll, $OutImportLib, $OqsHeader)) {
        Write-Host "==> liboqs: cached"
        return
    }

    Write-Host "==> liboqs ($InnerJobs jobs, $Generator, MSVC, static + shared)"
    Remove-Item $DepLibDir, (Join-Path $IncludeDir "oqs"), $DepIncludeDir, $StageStatic, $StageShared -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $WorkStatic, $WorkShared, $StageStatic, $StageShared, $DepLibDir, $DepIncludeDir | Out-Null

    $BaseArgs = @(
        "-S", "vendor\liboqs",
        "-G", $Generator,
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
        "-DOQS_BUILD_ONLY_LIB=ON",
        "-DOQS_USE_OPENSSL=OFF",
        "-DOQS_MINIMAL_BUILD=KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
    )

    if ($Generator -eq "Visual Studio 17 2022") {
        $BaseArgs += @("-A", "x64")
    } else {
        $BaseArgs += @("-DCMAKE_BUILD_TYPE=Release")
    }

    $Sccache = Get-Sccache
    if ($Sccache) {
        $BaseArgs += @("-DCMAKE_C_COMPILER_LAUNCHER=$Sccache", "-DCMAKE_CXX_COMPILER_LAUNCHER=$Sccache")
    }

    # Static pass.
    & cmake @BaseArgs "-B" $WorkStatic "-DCMAKE_INSTALL_PREFIX=$StageStatic" "-DBUILD_SHARED_LIBS=OFF"
    if ($LASTEXITCODE -ne 0) { throw "liboqs static configure failed" }

    & cmake --build $WorkStatic --config Release --target install --parallel $InnerJobs
    if ($LASTEXITCODE -ne 0) { throw "liboqs static build failed" }

    $BuiltStatic = Get-ChildItem $StageStatic -Recurse -Filter "oqs.lib" | Select-Object -First 1
    if (-not $BuiltStatic) { throw "oqs.lib not found after liboqs static build" }

    Copy-Item $BuiltStatic.FullName $OutStaticLib -Force
    Copy-Item (Join-Path $StageStatic "include\oqs") (Join-Path $DepIncludeDir "oqs") -Recurse -Force

    # Shared pass uses a separate CMake cache to avoid Ninja regeneration loops.
    & cmake @BaseArgs "-B" $WorkShared "-DCMAKE_INSTALL_PREFIX=$StageShared" "-DBUILD_SHARED_LIBS=ON"
    if ($LASTEXITCODE -ne 0) { throw "liboqs shared configure failed" }

    & cmake --build $WorkShared --config Release --target install --parallel $InnerJobs
    if ($LASTEXITCODE -ne 0) { throw "liboqs shared build failed" }

    $BuiltDll = Get-ChildItem $StageShared -Recurse -Filter "oqs.dll" | Select-Object -First 1
    $BuiltImport = Get-ChildItem $StageShared -Recurse -Filter "oqs.lib" | Select-Object -First 1
    if (-not $BuiltDll) { throw "oqs.dll not found after liboqs shared build" }
    if (-not $BuiltImport) { throw "oqs.lib import library not found after liboqs shared build" }

    Copy-Item $BuiltDll.FullName $OutDll -Force
    Copy-Item $BuiltImport.FullName $OutImportLib -Force

    Write-DependencyFingerprint "liboqs" $Fingerprint
    Remove-Item $WorkStatic, $WorkShared, $StageStatic, $StageShared -Recurse -Force
}

function Build-Rabe {
    $RustTarget = "x86_64-pc-windows-msvc"
    $Upstream = Get-FileDigest "vendor\librabe-ffi\UPSTREAM.md"
    $Lock = Get-FileDigest "vendor\librabe-ffi\Cargo.lock"
    $Header = Get-FileDigest "vendor\librabe-ffi\rabe.h"
    $Rustup = Get-Command rustup -ErrorAction SilentlyContinue
    $RustToolchain = $null

    if ($Rustup) {
        $Toolchains = @(& rustup toolchain list) | ForEach-Object { ($_ -split '\s+')[0] }
        $RustToolchain = $Toolchains | Where-Object { $_ -eq "stable-x86_64-pc-windows-msvc" } | Select-Object -First 1
        if (-not $RustToolchain) {
            $RustToolchain = $Toolchains | Where-Object { $_ -match 'x86_64-pc-windows-msvc$' } | Select-Object -First 1
        }
        if (-not $RustToolchain) {
            throw "No x86_64-pc-windows-msvc Rust toolchain is installed."
        }
        $RustVersion = (& rustup run $RustToolchain rustc -vV) -join [Environment]::NewLine
    } else {
        $Rustc = Get-Command rustc -ErrorAction SilentlyContinue
        if (-not $Rustc) { throw "rustc was not found" }
        $RustVersion = (& rustc -vV) -join [Environment]::NewLine
    }

    $NormalizeScript = Join-Path $PSScriptRoot "normalize-msvc-library.ps1"
    $NormalizeHash = Get-FileDigest $NormalizeScript
    $Fingerprint = Get-TextHash "rabe|$BuildVersion|windows|$Upstream|$Lock|$Header|$RustVersion|$RustTarget|$RustToolchain|release|$NormalizeHash"

    $DepLibDir = Join-Path $LibDir "rabe"
    $DepIncludeDir = Join-Path $IncludeDir "rabe"
    $Work = Join-Path $WorkDir "rabe-target"
    $OutLib = Join-Path $DepLibDir "librabe_ffi.lib"
    $RabeHeader = Join-Path $DepIncludeDir "rabe.h"

    if (Test-DependencyCache "rabe" $Fingerprint @($OutLib, $RabeHeader)) {
        Write-Host "==> librabe-ffi: cached"
        return
    }

    Write-Host "==> librabe-ffi ($InnerJobs jobs, target=$RustTarget)"
    Remove-Item $Work, $DepLibDir, $DepIncludeDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $DepLibDir, $DepIncludeDir | Out-Null

    if ($Rustup) {
        $InstalledTargets = @(& rustup target list --installed --toolchain $RustToolchain)
        if ($InstalledTargets -notcontains $RustTarget) {
            throw "Rust target $RustTarget is not installed for $RustToolchain"
        }
    }

    $env:CARGO_TARGET_DIR = $Work
    $Sccache = Get-Sccache
    if ($Sccache) { $env:RUSTC_WRAPPER = $Sccache }

    if ($RustToolchain) {
        & cargo "+$RustToolchain" build --locked --jobs $InnerJobs --target $RustTarget --manifest-path "vendor\librabe-ffi\Cargo.toml" --release
    } else {
        & cargo build --locked --jobs $InnerJobs --target $RustTarget --manifest-path "vendor\librabe-ffi\Cargo.toml" --release
    }
    if ($LASTEXITCODE -ne 0) { throw "librabe-ffi build failed" }

    $Release = Join-Path $Work "$RustTarget\release"
    $BuiltLib = Join-Path $Release "rabe_ffi.lib"
    if (-not (Test-Path $BuiltLib)) { throw "MSVC rabe_ffi.lib not found after Cargo build" }

    & $NormalizeScript -InputLib $BuiltLib -OutputLib $OutLib
    $BuiltDll = Join-Path $Release "rabe_ffi.dll"
    if (Test-Path $BuiltDll) { Copy-Item $BuiltDll $DepLibDir -Force }

    Copy-Item "vendor\librabe-ffi\rabe.h" $RabeHeader -Force
    Write-DependencyFingerprint "rabe" $Fingerprint @("rust_target=$RustTarget", "rust_toolchain=$RustToolchain")
    Remove-Item $Work -Recurse -Force
}

function Build-Tkn20 {
    $Upstream = Get-FileDigest "vendor\circl\UPSTREAM.md"
    $GoMod = Get-FileDigest "bindings\tkn20\go.mod"
    $GoSum = Get-FileDigest "bindings\tkn20\go.sum"
    $Bridge = Get-FileDigest "bindings\tkn20\cpabe_tkn20.go"
    $DefHash = Get-FileDigest "bindings\tkn20\libcpabe_tkn20.def"
    $GoVersion = (& go version)
    $GccPath = (Get-Command gcc).Source
    $GccMachine = (& gcc -dumpmachine).Trim()

    if ($GccMachine -notmatch 'mingw') {
        throw "Windows TKN20 CGO requires MinGW-w64 gcc; detected: $GccMachine"
    }

    $Fingerprint = Get-TextHash "tkn20|$BuildVersion|windows|$Upstream|$GoMod|$GoSum|$Bridge|$DefHash|$GoVersion|$GccPath|$GccMachine|dll-c-abi"

    $DepLibDir = Join-Path $LibDir "tkn20"
    $DepIncludeDir = Join-Path $IncludeDir "tkn20"
    $Work = Join-Path $WorkDir "tkn20"
    $OutDll = Join-Path $DepLibDir "libcpabe_tkn20.dll"
    $OutLib = Join-Path $DepLibDir "libcpabe_tkn20.lib"
    $TknHeader = Join-Path $DepIncludeDir "cpabe_tkn20.h"

    if (Test-DependencyCache "tkn20" $Fingerprint @($OutDll, $OutLib, $TknHeader)) {
        Write-Host "==> CIRCL/TKN20: cached"
        return
    }

    Write-Host "==> CIRCL/TKN20 ($InnerJobs jobs, MinGW CGO -> C ABI DLL -> MSVC import lib)"
    Remove-Item $Work, $DepLibDir, $DepIncludeDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $Work, $DepLibDir, $DepIncludeDir | Out-Null

    Push-Location "bindings\tkn20"
    try {
        $env:CGO_ENABLED = "1"
        $env:CC = $GccPath
        & go build -p $InnerJobs -buildmode=c-shared -o (Join-Path $Work "libcpabe_tkn20.dll") .
        if ($LASTEXITCODE -ne 0) { throw "TKN20 Go bridge build failed" }
    } finally {
        Pop-Location
    }

    Copy-Item (Join-Path $Work "libcpabe_tkn20.dll") $OutDll -Force
    Copy-Item (Join-Path $Work "libcpabe_tkn20.h") $TknHeader -Force
    Copy-Item "bindings\tkn20\libcpabe_tkn20.def" (Join-Path $DepLibDir "libcpabe_tkn20.def") -Force

    & lib.exe /NOLOGO "/DEF:$DepLibDir\libcpabe_tkn20.def" "/OUT:$OutLib" /MACHINE:X64
    if ($LASTEXITCODE -ne 0) { throw "TKN20 MSVC import library generation failed" }

    Write-DependencyFingerprint "tkn20" $Fingerprint @(
        "go_cc=$GccMachine",
        "boundary=C-ABI-DLL",
        "consumer_abi=MSVC"
    )
    Remove-Item $Work -Recurse -Force
}

function Start-DependencyProcess([string]$Name, [int]$JobCount) {
    $Args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $PSCommandPath + '"'),
        "-Dependency", $Name,
        "-Jobs", $JobCount
    )
    $Process = Start-Process -FilePath "powershell.exe" -ArgumentList $Args -NoNewWindow -PassThru
    # Windows PowerShell can lose ExitCode after waiting unless the handle is retained.
    $null = $Process.Handle
    return [PSCustomObject]@{ Name = $Name; Process = $Process }
}

function Wait-DependencyProcesses([System.Collections.ArrayList]$Processes) {
    $Failures = @()
    foreach ($Worker in $Processes) {
        try {
            $Worker.Process.WaitForExit()
            $ExitCode = $Worker.Process.ExitCode
            if ($null -eq $ExitCode) {
                $Failures += "$($Worker.Name) (exit code unavailable)"
            } elseif ($ExitCode -ne 0) {
                $Failures += "$($Worker.Name) (exit code $ExitCode)"
            }
        } finally {
            $Worker.Process.Dispose()
        }
    }
    if ($Failures.Count -gt 0) { throw "Dependency builds failed: $($Failures -join ', ')" }
}

function Show-Outputs {
    Write-Host ""
    Write-Host "================================================================"
    Write-Host " Dependency build complete: windows"
    Write-Host " Includes : build/deps/windows/include/"
    Write-Host " Libraries: build/deps/windows/lib/"
    Write-Host "----------------------------------------------------------------"

    foreach ($Name in @("cryptopp", "liboqs", "rabe", "tkn20")) {
        Write-Host " [$Name]"
        Write-Host "   include: build/deps/windows/include/$Name/"
        Write-Host "   lib    : build/deps/windows/lib/$Name/"
        $Dir = Join-Path $LibDir $Name
        if (Test-Path $Dir) {
            Get-ChildItem $Dir -File | Where-Object { $_.Name -notin @(".fingerprint", ".dll-fingerprint") } |
                ForEach-Object { Write-Host ("            " + $_.Name) }
        }
    }
    Write-Host "================================================================"
}

function Write-ReadyMarker {
    $Ready = Join-Path $LibDir ".ready"
    @(
        "platform=windows",
        "build_version=$BuildVersion",
        "cryptopp=$((Get-FileHash -Algorithm SHA256 (Get-FingerprintPath 'cryptopp')).Hash.ToLowerInvariant())",
        "cryptopp_dll=$((Get-FileHash -Algorithm SHA256 (Join-Path $LibDir 'cryptopp\.dll-fingerprint')).Hash.ToLowerInvariant())",
        "liboqs=$((Get-FileHash -Algorithm SHA256 (Get-FingerprintPath 'liboqs')).Hash.ToLowerInvariant())",
        "rabe=$((Get-FileHash -Algorithm SHA256 (Get-FingerprintPath 'rabe')).Hash.ToLowerInvariant())",
        "tkn20=$((Get-FileHash -Algorithm SHA256 (Get-FingerprintPath 'tkn20')).Hash.ToLowerInvariant())"
    ) | Set-Content $Ready
}

function Build-All {
    $Priority = @("liboqs", "cryptopp", "rabe", "tkn20")
    $Count = $Priority.Count

    if ($TotalJobs -lt $Count) {
        Write-Host "Dependency worker budget: total=$TotalJobs; up to $TotalJobs dependencies concurrently (1 job each)"
        for ($Offset = 0; $Offset -lt $Count; $Offset += $TotalJobs) {
            $Processes = [System.Collections.ArrayList]::new()
            $End = [Math]::Min($Offset + $TotalJobs, $Count)

            for ($i = $Offset; $i -lt $End; $i++) {
                [void]$Processes.Add((Start-DependencyProcess $Priority[$i] 1))
            }
            Wait-DependencyProcesses $Processes
        }
    } else {
        $Base = [Math]::Floor($TotalJobs / $Count)
        $Extra = $TotalJobs % $Count
        $Processes = [System.Collections.ArrayList]::new()

        Write-Host "Dependency worker budget: total=$TotalJobs"
        for ($i = 0; $i -lt $Count; $i++) {
            $Assigned = $Base
            if ($i -lt $Extra) { $Assigned++ }

            Write-Host ("  {0}: {1}" -f $Priority[$i], $Assigned)
            [void]$Processes.Add((Start-DependencyProcess $Priority[$i] $Assigned))
        }
        Wait-DependencyProcesses $Processes
    }

    Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue

    # Migrate/clean the legacy layout. Keep only the stable consumer surface.
    Get-ChildItem $DepsDir -Force | Where-Object {
        $_.Name -notin @("include", "lib")
    } | Remove-Item -Recurse -Force

    Write-ReadyMarker
    Show-Outputs
}

switch ($Dependency) {
    "cryptopp" { Build-CryptoPP }
    "liboqs"   { Build-LibOqs }
    "rabe"     { Build-Rabe }
    "tkn20"    { Build-Tkn20 }
    "all"      { Build-All }
}
