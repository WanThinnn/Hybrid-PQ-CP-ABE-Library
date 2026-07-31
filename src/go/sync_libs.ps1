# Smart Sync built C++ libraries to Go plugin directory

$TargetDir = "vault-plugin-abe\lib"

if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir | Out-Null
}

$updated = $false

# Function to copy if newer
function Copy-IfNewer {
    param ($SourceDir, $DestDir)
    if (Test-Path $SourceDir) {
        $files = Get-ChildItem -Path $SourceDir -File
        foreach ($file in $files) {
            $destFile = Join-Path $DestDir $file.Name
            if (-not (Test-Path $destFile) -or ($file.LastWriteTime -gt (Get-Item $destFile).LastWriteTime)) {
                Copy-Item -Path $file.FullName -Destination $destFile -Force
                Write-Host "Synced: $($file.Name)" -ForegroundColor Cyan
                $script:updated = $true
            }
        }
    }
}

Copy-IfNewer -SourceDir "..\cpp\lib\static" -DestDir $TargetDir
Copy-IfNewer -SourceDir "..\cpp\lib\dynamic" -DestDir $TargetDir

if (-not $updated) {
    Write-Host "All libraries are up-to-date. No sync needed." -ForegroundColor DarkGray
} else {
    Write-Host "Libraries synced to $TargetDir successfully!" -ForegroundColor Green
}
