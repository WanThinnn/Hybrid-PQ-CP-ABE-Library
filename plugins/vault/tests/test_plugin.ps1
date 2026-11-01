$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '../../..')
try {
    & make test-vault @args
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
