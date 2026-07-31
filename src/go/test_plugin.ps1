Write-Host "Syncing latest C++ libraries if needed..."
.\sync_libs.ps1

Write-Host "Building everything inside Multi-stage Docker..."
docker build -t vault-ubuntu -f D:\Documents\UIT\ABE\Hybrid-CP-ABE-Library\src\go\Dockerfile D:\Documents\UIT\ABE\Hybrid-CP-ABE-Library

if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed!"
    exit 1
}

Write-Host "Starting Vault dev server in Docker (Windows)..."
docker rm -f vault-dev 2>$null

# Run vault in dev mode. The plugin is already compiled and baked into the image.
docker run -d --name vault-dev -p 8201:8200 --cap-add=IPC_LOCK vault-ubuntu

Write-Host "Waiting for Vault to start..."
Start-Sleep -Seconds 5

Write-Host "Checking plugin dependencies in Docker:"
docker exec vault-dev ldd /vault/plugins/vault-plugin-abe

Write-Host "Registering plugin..."
docker exec vault-dev sh -c "sha256sum /vault/plugins/vault-plugin-abe | awk '{print `$1}' > /tmp/sha.txt"
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev sh -c 'vault plugin register -sha256=$(cat /tmp/sha.txt) secret vault-plugin-abe'

Write-Host "Enabling plugin at abe/ ..."
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault secrets enable -path=abe vault-plugin-abe

Write-Host "Testing Setup (TKN20)..."
$setupStr = docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/setup scheme=tkn20
$setupJson = $setupStr | ConvertFrom-Json
$PK = $setupJson.data.public_key
Write-Host "Setup successful."

Write-Host "Testing GenKey..."
$genkeyStr = docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/genkey attributes="role:admin" scheme=tkn20
$genkeyJson = $genkeyStr | ConvertFrom-Json
$SK = $genkeyJson.data.secret_key
Write-Host "GenKey successful."

Write-Host "Testing Encrypt..."
$encryptStr = docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/encrypt plaintext="SGVsbG8gVmF1bHQ=" policy="role:admin" scheme=tkn20 public_key=$PK
$encryptJson = $encryptStr | ConvertFrom-Json
$CT = $encryptJson.data.ciphertext
Write-Host "Encrypt successful."

Write-Host "Testing Decrypt..."
$decryptStr = docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/decrypt ciphertext=$CT secret_key=$SK
$decryptJson = $decryptStr | ConvertFrom-Json
$PT = $decryptJson.data.plaintext

Write-Host "Decrypted plaintext: $PT"
Write-Host "Expected: SGVsbG8gVmF1bHQ="
if ($PT -eq "SGVsbG8gVmF1bHQ=") {
    Write-Host "SUCCESS!"
} else {
    Write-Host "FAILURE!"
}
