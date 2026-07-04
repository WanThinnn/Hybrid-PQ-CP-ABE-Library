#!/bin/bash

# Ensure we are in the Go plugin directory
cd "$(dirname "$0")"

echo "Building everything inside Multi-stage Docker..."
docker build -t vault-ubuntu -f Dockerfile ../..
if [ $? -ne 0 ]; then
  echo "Docker build failed!"
  exit 1
fi

echo "Starting Vault dev server in Docker..."
docker rm -f vault-dev 2>/dev/null || true

# Run vault in dev mode. The plugin is already compiled and baked into the image.
docker run -d --name vault-dev -p 8201:8200 --cap-add=IPC_LOCK vault-ubuntu

echo "Waiting for Vault to start..."
sleep 5

echo "Checking plugin dependencies in Docker:"
docker exec vault-dev ldd /vault/plugins/vault-plugin-abe

echo "Registering plugin..."
docker exec vault-dev sh -c "sha256sum /vault/plugins/vault-plugin-abe | awk '{print \$1}' > /tmp/sha.txt"
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev sh -c 'vault plugin register -sha256=$(cat /tmp/sha.txt) secret vault-plugin-abe'

echo "Enabling plugin at abe/ ..."
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault secrets enable -path=abe vault-plugin-abe

echo "Testing Setup (TKN20)..."
SETUP_JSON=$(docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/setup scheme=tkn20)
PK=$(echo $SETUP_JSON | grep -o '"public_key":"[^"]*' | cut -d'"' -f4)
echo "Setup successful."

echo "Testing GenKey..."
GENKEY_JSON=$(docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/genkey attributes="role:admin" scheme=tkn20)
SK=$(echo $GENKEY_JSON | grep -o '"secret_key":"[^"]*' | cut -d'"' -f4)
echo "GenKey successful."

echo "Testing Encrypt..."
ENCRYPT_JSON=$(docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/encrypt plaintext="SGVsbG8gVmF1bHQ=" policy="role:admin" scheme=tkn20 public_key="$PK")
CT=$(echo $ENCRYPT_JSON | grep -o '"ciphertext":"[^"]*' | cut -d'"' -f4)
echo "Encrypt successful."

echo "Testing Decrypt..."
DECRYPT_JSON=$(docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write -format=json abe/decrypt ciphertext="$CT" secret_key="$SK")
PT=$(echo $DECRYPT_JSON | grep -o '"plaintext":"[^"]*' | cut -d'"' -f4)

echo "Decrypted plaintext: $PT"
echo "Expected: SGVsbG8gVmF1bHQ="

if [ "$PT" = "SGVsbG8gVmF1bHQ=" ]; then
    echo "SUCCESS!"
else
    echo "FAILURE!"
fi
