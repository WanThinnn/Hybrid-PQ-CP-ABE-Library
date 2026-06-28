# HashiCorp Vault Plugin: Hybrid Post-Quantum CP-ABE

This directory contains the Go implementation of a custom HashiCorp Vault plugin that integrates a Hybrid Post-Quantum Ciphertext-Policy Attribute-Based Encryption (CP-ABE) scheme.

The core cryptographic algorithms are implemented in C++ (located in `../cpp/`) and are compiled natively into this Go plugin via CGO. 

## Requirements

The most reliable way to build and test this plugin is by using **Docker**, because compiling the plugin requires C++17, CMake, and development libraries (like `libssl-dev`) that can be cumbersome to set up on Windows.

- Docker
- PowerShell (Windows) or Bash (Linux/macOS)

## Quick Start (Automated Build & Test)

We provide test scripts that automate the entire process:
1. Builds a multi-stage Docker image (`vault-ubuntu`).
2. Compiles the C++ core and Go plugin natively inside the container.
3. Spawns a Vault development server.
4. Registers the plugin and runs a complete Setup -> GenKey -> Encrypt -> Decrypt workflow.

**On Windows:**
```powershell
.\test_plugin.ps1
```

**On Linux/macOS:**
```bash
./test_plugin.sh
```

## Manual Build and Registration (Docker)

If you wish to run the container and explore Vault manually, you can follow these steps:

### 1. Build the Docker Image
From the **root of the repository** (where the `src/` folder is located), run:
```bash
docker build -t vault-ubuntu -f src/go/Dockerfile .
```
This multi-stage Dockerfile resolves C++ dependencies, compiles the static libraries, compiles the Go plugin via CGO, and finally creates a lightweight Vault image with the plugin already placed in `/vault/plugins/vault-plugin-abe`.

### 2. Start Vault Dev Server
```bash
docker run -d --name vault-dev -p 8200:8200 --cap-add=IPC_LOCK vault-ubuntu
```

### 3. Register and Enable the Plugin
Execute the following commands against the running container:
```bash
# Get the SHA256 sum of the plugin binary
docker exec vault-dev sh -c "sha256sum /vault/plugins/vault-plugin-abe | awk '{print \$1}' > /tmp/sha.txt"

# Register the plugin with Vault
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev sh -c 'vault plugin register -sha256=$(cat /tmp/sha.txt) secret vault-plugin-abe'

# Enable the secrets engine at the "abe/" path
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='root' vault-dev vault secrets enable -path=abe vault-plugin-abe
```

## API Usage

Once the plugin is enabled at `abe/`, you can use the Vault CLI or REST API to interact with it.

### Setup Scheme
Initializes the system. Vault stores the Master Secret Key (MSK) securely and returns the Public Key (PK) as a Base64 string.
```bash
vault write abe/setup scheme=tkn20
```

### Generate Secret Key
Generates a user's decryption key based on their attributes (returns a Base64 string).
```bash
vault write abe/genkey scheme=tkn20 attributes="role:admin"
```

### Encrypt Data
Encrypts Base64 plaintext according to an access policy. You must provide the Public Key obtained from setup.
```bash
vault write abe/encrypt scheme=tkn20 policy="role:admin" public_key="<BASE64_PK>" plaintext="SGVsbG8gVmF1bHQ="
```

### Decrypt Data
Decrypts a ciphertext using a user's Secret Key.
```bash
vault write abe/decrypt scheme=tkn20 ciphertext="<CIPHERTEXT>" secret_key="<BASE64_SK>"
```

## Local Development (Without Docker)

To develop locally, your host machine must fulfill the following CGO requirements:
- `gcc` or `g++` (e.g. MinGW-w64 on Windows, `build-essential` on Linux)
- The static C++ libraries compiled in `../cpp/lib/static/`
- Run `go build -o build/vault-plugin-abe ./cmd/vault-plugin-abe/main.go` inside the `vault-plugin-abe` folder.
*(Note: On Windows, CGO linking against Unix POSIX libraries like `-ldl` is not supported natively, hence Docker is highly recommended.)*
