# HashiCorp Vault integration

The Linux ABE secrets engine runs the native library inside Vault. Each
mount stores one authority and keeps its master secret in Vault storage.
Applications can issue user keys and encrypt data through the mount.
[Plugin source and build instructions](../../plugins/vault/README.md)

## Install and mount

Use the Linux Vault plugin release archive or build it with `make vault`.
Place `vault-plugin-abe` and `libhybrid-pq-cp-abe.so` together in the directory
configured as Vault's `plugin_directory`. Register the executable with its
SHA-256 checksum and enable a mount named `abe`.

```sh
PLUGIN_DIR=/absolute/path/to/plugin-directory
sha256=$(sha256sum "$PLUGIN_DIR/vault-plugin-abe" | cut -d ' ' -f 1)
vault plugin register -sha256="$sha256" -command=vault-plugin-abe secret vault-plugin-abe
vault secrets enable -path=abe vault-plugin-abe
```

## Provision a CoverCrypt authority

From the library repo, use the example dimensions file below. Vault CLI reads
`@file` on the client and sends the JSON in the request. Run this on a fresh
mount. `create_only=true` protects an existing authority from replacement.

```sh
public_key=$(vault write -field=public_key abe/setup scheme=covercrypt \
  config_json=@scripts/covercrypt-demo.json mode=hybridized pqc=false create_only=true)
user_key=$(vault write -field=secret_key abe/genkey scheme=covercrypt \
  attributes='Department::IT Level::ADMIN')
ciphertext=$(vault write -field=ciphertext abe/encrypt scheme=covercrypt \
  public_key="$public_key" plaintext=aGVsbG8= policy='Department::IT && Level::ADMIN')
vault write -field=plaintext abe/decrypt secret_key="$user_key" \
  ciphertext="$ciphertext" | base64 --decode
```

The example recovers `hello`. Treat user keys returned by `genkey` as secrets.
Setup can enable ML-DSA with `pqc=true`. Supply the trusted `pqc_public_key`
to require verification on decryption. [Signed workflow](../../plugins/vault/README.md#covercrypt-configuration-and-api)

Use `abe/add_dimension` to grow a CoverCrypt authority and save the returned
public key. Issue new user keys to grant rights in the new dimension.
[Authority lifecycle, references, and recovery](../../plugins/vault/AUTHORITY.md) · [Integration tests](../../plugins/vault/TESTING.md)
