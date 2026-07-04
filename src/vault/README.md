# Vault Plugin Python Test Suite

This directory contains a Python script (`test_vault.py`) that demonstrates how to interact with the custom HashiCorp Vault Secrets Engine via its REST API.

The script performs a complete end-to-end test of the `AC17` and `TKN20` schemes, covering:
1. **`setup`**: Generating the Master Secret Key inside Vault and returning the Public Key.
2. **`genkey`**: Generating User Secret Keys bound to specific attributes.
3. **`encrypt`**: Encrypting a message according to an access policy.
4. **`decrypt`**: Decrypting a ciphertext.

## Prerequisites

1. **Python 3.x** must be installed.
2. Install the required `requests` library:
   ```bash
   pip install requests
   ```
3. A Vault instance must be running with the CP-ABE plugin registered and enabled at the `abe/` path.
   - If you are testing within this repository, you should first start the Docker-based Vault server by running the automated script in `../go/`:
     - **Windows**: `.\test_plugin.ps1`
     - **Linux/macOS**: `./test_plugin.sh`
   - These scripts will automatically compile the plugin, register it, and launch a Vault development server listening on `http://127.0.0.1:8201`.

## Running the Test

Once the Vault server is running, simply execute the Python script:

```bash
python test_vault.py
```

### Expected Output

You should see both the `TKN20` and `AC17` schemes being tested successfully.
- The `Admin` (who possesses the `role:admin` attribute) will successfully decrypt the secret message.
- The `Guest` (who possesses the `role:guest` attribute) will fail to decrypt the message, and Vault will explicitly reject the request with an `unauthorized access` error.

This behavior mathematically guarantees that Cryptographic Access Control policies are being enforced securely by the Vault Plugin.
