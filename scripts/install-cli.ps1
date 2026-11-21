param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$Runtime,
    [Parameter(Mandatory = $true)][string]$IncludeDirectory,
    [Parameter(Mandatory = $true)][string]$StaticLibrary,
    [Parameter(Mandatory = $true)][string]$SharedLibrary,
    [Parameter(Mandatory = $true)][string]$SharedImportLibrary,
    [Parameter(Mandatory = $true)][string]$RuntimeImportLibrary,
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\pq-cp-abe'),
    [switch]$SkipPathUpdate
)

$ErrorActionPreference = 'Stop'
$prefixPath = [IO.Path]::GetFullPath($Prefix)
$bin = Join-Path $prefixPath 'bin'
$include = Join-Path $prefixPath 'include'
$lib = Join-Path $prefixPath 'lib'
$exeSource = (Resolve-Path -LiteralPath $Executable).Path
$dllSource = (Resolve-Path -LiteralPath $Runtime).Path
$includeSource = (Resolve-Path -LiteralPath $IncludeDirectory).Path
$librarySources = @(
    (Resolve-Path -LiteralPath $StaticLibrary).Path
    (Resolve-Path -LiteralPath $SharedLibrary).Path
    (Resolve-Path -LiteralPath $SharedImportLibrary).Path
    (Resolve-Path -LiteralPath $RuntimeImportLibrary).Path
)
if ($bin.Contains(';')) { throw 'The installation path must not contain a semicolon.' }

New-Item -ItemType Directory -Force -Path $bin, $include, $lib | Out-Null
Copy-Item -LiteralPath $exeSource -Destination (Join-Path $bin 'pq-cp-abe.exe') -Force
Copy-Item -LiteralPath $dllSource -Destination (Join-Path $bin 'libcpabe_tkn20.dll') -Force
Copy-Item -LiteralPath $librarySources[1] -Destination (Join-Path $bin 'libhybrid-pq-cp-abe.dll') -Force
Copy-Item -Path (Join-Path $includeSource '*') -Destination $include -Recurse -Force
foreach ($librarySource in $librarySources) {
    Copy-Item -LiteralPath $librarySource -Destination $lib -Force
}
Write-Host "Installed pq-cp-abe in $prefixPath"
Write-Host "  Headers: $include"
Write-Host "  Libraries: $lib"

if (-not $SkipPathUpdate) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $existing = $userPath -split ';' | Where-Object {
        [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')).TrimEnd('\', '/') -ieq $bin.TrimEnd('\', '/')
    }
    if (-not $existing) {
        $updated = if ($userPath) { $userPath.TrimEnd(';') + ';' + $bin } else { $bin }
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    }
    Write-Host 'Open a new terminal to run pq-cp-abe from PATH.'
}
