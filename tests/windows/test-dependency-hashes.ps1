Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$Tokens = $null
$ParseErrors = $null
$Ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'scripts\build-deps.ps1'), [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw ($ParseErrors | Out-String) }
foreach ($FunctionName in @('Get-FileDigest', 'Get-FingerprintPath', 'Write-ReadyMarker')) {
    $Definition = $Ast.Find({ param($Node)
        $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $FunctionName
    }, $true)
    Invoke-Expression $Definition.Extent.Text
}
# Fail even if Get-FileHash happens to be installed on the test host.
function Get-FileHash { throw 'The dependency script must not call Get-FileHash' }
$OriginalLocation = (Get-Location).Path
$TestPrefix = Join-Path $Root 'build\test-dependency-hashes-'
$TestDirectory = $TestPrefix + [Guid]::NewGuid().ToString('N')
[void][IO.Directory]::CreateDirectory($TestDirectory)
try {
    Set-Location $TestDirectory
    [IO.File]::WriteAllBytes((Join-Path $TestDirectory 'empty.bin'), [byte[]]@())
    [IO.File]::WriteAllBytes((Join-Path $TestDirectory 'abc with spaces.bin'), [byte[]]@(97, 98, 99))
    $EmptyDigest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    $AbcDigest = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    if ((Get-FileDigest 'empty.bin') -cne $EmptyDigest) { throw 'Empty-file SHA256 mismatch' }
    if ((Get-FileDigest 'abc with spaces.bin') -cne $AbcDigest) { throw 'SHA256 or PowerShell-relative path mismatch' }
    [IO.File]::Move((Join-Path $TestDirectory 'abc with spaces.bin'), (Join-Path $TestDirectory 'renamed.bin'))
    Write-Host 'PASS: SHA256 vectors, paths with spaces, PowerShell location, and stream disposal'
    try {
        $null = Get-FileDigest 'missing.bin'
        throw 'Expected a missing-file error'
    } catch {
        if ($_.Exception.Message -eq 'Expected a missing-file error') { throw }
    }
    $LibDir = Join-Path $TestDirectory 'lib'
    $BuildVersion = 'test'
    foreach ($Name in @('cryptopp', 'liboqs', 'rabe', 'tkn20', 'covercrypt')) {
        [void][IO.Directory]::CreateDirectory((Join-Path $LibDir $Name))
        [IO.File]::WriteAllBytes((Get-FingerprintPath $Name), [byte[]]@(97, 98, 99))
    }
    [IO.File]::WriteAllBytes((Join-Path $LibDir 'cryptopp\.dll-fingerprint'), [byte[]]@(97, 98, 99))
    Write-ReadyMarker
    $Ready = [IO.File]::ReadAllText((Join-Path $LibDir '.ready')) -split '\r?\n'
    foreach ($Name in @('cryptopp', 'cryptopp_dll', 'liboqs', 'rabe', 'tkn20', 'covercrypt')) {
        if ($Ready -cnotcontains "$Name=$AbcDigest") { throw "Ready-marker digest mismatch: $Name" }
    }
    Write-Host 'PASS: all six ready-marker digests without Get-FileHash'
} finally {
    Set-Location $OriginalLocation
    $CleanupPath = [IO.Path]::GetFullPath($TestDirectory)
    if (-not $CleanupPath.StartsWith($TestPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside the generated test directory'
    }
    [IO.Directory]::Delete($CleanupPath, $true)
}
