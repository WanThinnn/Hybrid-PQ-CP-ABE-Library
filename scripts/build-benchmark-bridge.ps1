param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'

$artifactDir = Join-Path $Root 'build\artifacts\windows'
$depsDir = Join-Path $Root 'build\deps\windows'
$source = Join-Path $Root 'benchmark\native_primitive_bridge.cpp'
$staticLib = Join-Path $artifactDir 'libhybrid-pq-cp-abe.lib'
$tkn20Import = Join-Path $depsDir 'lib\tkn20\libcpabe_tkn20.lib'
$tkn20Dll = Join-Path $depsDir 'lib\tkn20\libcpabe_tkn20.dll'
$outDir = Join-Path $artifactDir 'benchmark'
$outDll = Join-Path $outDir 'native_primitive_bridge.dll'
$outImport = Join-Path $outDir 'native_primitive_bridge.lib'
$outObj = Join-Path $outDir 'native_primitive_bridge.obj'
$outPdb = Join-Path $outDir 'native_primitive_bridge.pdb'
$tempDir = Join-Path $Root 'build\tmp\benchmark-bridge'

foreach ($required in @($source, $staticLib, $tkn20Import, $tkn20Dll)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw ('Missing existing build artifact: ' + $required + [Environment]::NewLine +
               'Build the core/dependencies separately before building the benchmark bridge.')
    }
}

$vsRoots = @(
    'C:\Program Files\Microsoft Visual Studio\18\Community',
    'C:\Program Files\Microsoft Visual Studio\18\BuildTools',
    'C:\Program Files\Microsoft Visual Studio\2022\Community',
    'C:\Program Files\Microsoft Visual Studio\2022\BuildTools',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
)

$vsRoot = $vsRoots | Where-Object { Test-Path (Join-Path $_ 'Common7\Tools\VsDevCmd.bat') } | Select-Object -First 1
if (-not $vsRoot) {
    throw 'Visual Studio C++ toolchain not found. Expected VsDevCmd.bat from Visual Studio 18/2022.'
}

$vsDevCmd = Join-Path $vsRoot 'Common7\Tools\VsDevCmd.bat'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$env:TEMP = $tempDir
$env:TMP = $tempDir

$includeRoot = Join-Path $Root 'include'
$depsInclude = Join-Path $depsDir 'include'
$oqsInclude = Join-Path $depsInclude 'liboqs'
$tkn20Include = Join-Path $depsInclude 'tkn20'

$compile = @(
    'cl.exe', '/nologo', '/MD', '/GS', '/O2', '/EHsc', '/utf-8',
    ('/I"' + $includeRoot + '"'),
    ('/I"' + $depsInclude + '"'),
    ('/I"' + $oqsInclude + '"'),
    ('/I"' + $tkn20Include + '"'),
    '/LD',
    ('/Fo:"' + $outObj + '"'),
    ('"' + $source + '"'),
    ('/Fe:"' + $outDll + '"'),
    '/link', '/MACHINE:X64', '/IGNORE:4099',
    ('/PDB:"' + $outPdb + '"'),
    ('"' + $staticLib + '"'),
    ('"' + $tkn20Import + '"'),
    'bcrypt.lib', 'advapi32.lib', 'ntdll.lib', 'userenv.lib', 'ws2_32.lib',
    ('/IMPLIB:"' + $outImport + '"')
) -join ' '

$command = 'call "' + $vsDevCmd + '" -arch=x64 -host_arch=x64 >nul && ' + $compile
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    throw "Benchmark bridge build failed with exit code $LASTEXITCODE"
}

Copy-Item -Force $tkn20Dll (Join-Path $outDir 'libcpabe_tkn20.dll')
Get-ChildItem $outDir -Filter '*.exp' -ErrorAction SilentlyContinue | Remove-Item -Force

Write-Host "Done! Benchmark primitive bridge: $outDll"
