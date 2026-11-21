param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$Runtime,
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\pq-cp-abe'),
    [switch]$SkipPathUpdate
)

$ErrorActionPreference = 'Stop'
$bin = Join-Path ([IO.Path]::GetFullPath($Prefix)) 'bin'
$exeSource = (Resolve-Path -LiteralPath $Executable).Path
$dllSource = (Resolve-Path -LiteralPath $Runtime).Path
if ($bin.Contains(';')) { throw 'The installation path must not contain a semicolon.' }

New-Item -ItemType Directory -Force -Path $bin | Out-Null
Copy-Item -LiteralPath $exeSource -Destination (Join-Path $bin 'pq-cp-abe.exe') -Force
Copy-Item -LiteralPath $dllSource -Destination (Join-Path $bin 'libcpabe_tkn20.dll') -Force
Write-Host "Installed pq-cp-abe in $bin"

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
