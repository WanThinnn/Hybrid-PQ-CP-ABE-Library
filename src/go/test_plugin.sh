#!/bin/bash

# Ensure we are in the Go plugin directory
cd /mnt/d/Documents/UIT/ABE/Hybrid-CP-ABE-Library/src/go/vault-plugin-abe

echo "Building Go plugin..."
go mod tidy
export CGO_LDFLAGS="-Wl,-rpath=/usr/lib"
go build -o build/vault-plugin-abe ./cmd/vault-plugin-abe/main.go
if [ $? -ne 0 ]; then
  echo "Build failed!"
  exit 1
fi

echo "Building custom Ubuntu Vault Docker image..."
docker build -t vault-ubuntu -f /mnt/d/Documents/UIT/ABE/Hybrid-CP-ABE-Library/src/go/Dockerfile /mnt/d/Documents/UIT/ABE/Hybrid-CP-ABE-Library

# Stop and remove any existing vault container
docker rm -f vault-dev || true

docker run -d --name vault-dev -p 8200:8200 --cap-add=IPC_LOCK -v $(pwd)/build:/vault/plugins vault-ubuntu

echo "Waiting for Vault to start..."
sleep 5

echo "Registering plugin..."
# Get SHA256 of the plugin from inside the container
SHA256=$(docker exec vault-dev shasum -a 256 /vault/plugins/vault-plugin-abe | cut -d ' ' -f 1)

# Register the plugin in the catalog
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault plugin register -sha256=${SHA256} secret vault-plugin-abe

echo "Enabling plugin at abe/ ..."
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault secrets enable -path=abe vault-plugin-abe

echo "Testing Setup (TKN20)..."
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write abe/setup scheme=tkn20 > setup.txt
cat setup.txt

echo "Testing GenKey..."
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write abe/genkey attributes="role:admin" scheme=tkn20 > sk.txt
cat sk.txt

echo "Testing Encrypt..."
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write abe/encrypt plaintext="SGVsbG8gVmF1bHQ=" policy="role:admin" scheme=tkn20 > ct.txt
cat ct.txt
CT=$(grep ciphertext ct.txt | awk '{print $2}')

echo "Testing Decrypt..."
SK=$(grep secret_key sk.txt | awk '{print $2}')
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault write abe/decrypt ciphertext=$CT secret_key=$SK > pt.txt
cat pt.txt

echo "Done! Decrypted plaintext should be SGVsbG8gVmF1bHQ="
