---
icon: lucide/terminal
---

# CLI, builds and publishing

The npm package exposes a Node.js CLI backed by WASM. It uses **real host paths** by copying files into the module's virtual filesystem before invoking native functions, then writing results back to disk.

~~~sh
npx @wanthinnn/pq-cp-abe --help
npx @wanthinnn/pq-cp-abe encrypt --help
npx @wanthinnn/pq-cp-abe --version
npx @wanthinnn/pq-cp-abe --test
~~~

You may use the equivalent `pq-cp-abe` command if the package is installed into your project's local `node_modules/.bin`. Supported primary commands: `setup`, `genkey`, `encrypt`, `decrypt`, `setup_buffer`, `genkey_buffer`, `encrypt_buffer`, `decrypt_buffer`, `add_dimension`, `add_attribute`, `version`.

## CoverCrypt dimensions

Create `dimensions.json`:

~~~json
{
  "dimensions": [
    {"name": "department", "attributes": ["finance", "it"]},
    {"name": "level", "attributes": ["user", "admin"]}
  ]
}
~~~

On setup, pass `--config dimensions.json`, or define `HCPABE_COVERCRYPT_CONFIG`. The optional `--mode hybridized|post_quantum|classic` chooses key-encapsulation mode.

## Unsigned encryption

Create a directory `keys` and file `message.txt` first:

~~~sh
npx @wanthinnn/pq-cp-abe --setup --scheme covercrypt --config dimensions.json --file keys
npx @wanthinnn/pq-cp-abe --genkey --scheme covercrypt --master-key keys/cpabe_msk.key --attributes "department::finance" --user-key finance.key
npx @wanthinnn/pq-cp-abe --encrypt --scheme covercrypt --public-key keys/cpabe_pk.key --file message.txt --policy "department::finance" --ciphertext message.enc
npx @wanthinnn/pq-cp-abe --decrypt --user-key finance.key --ciphertext message.enc --output recovered.txt
~~~

For AC17/TKN20 use `--scheme ac17` or `--scheme tkn20` consistently in setup, genkey and encrypt; decryption detects scheme in ciphertext.

The npm CLI refuses to overwrite an existing **new output**: choose unused output paths. The naming convention is `keys/cpabe_pk.key` + `keys/cpabe_msk.key` when targeting an existing directory, or `prefix_pk.key` + `prefix_msk.key` when using a prefix.

## Signed encryption and verification

~~~sh
npx @wanthinnn/pq-cp-abe --setup --scheme covercrypt --config dimensions.json --file signed --with-signing-keys --ml-dsa 65
npx @wanthinnn/pq-cp-abe --genkey --scheme covercrypt --master-key signed_msk.key --attributes "department::finance" --user-key signed-user.key
npx @wanthinnn/pq-cp-abe --encrypt --scheme covercrypt --sign --public-key signed_pk.key --signing-key signed_ml-dsa_sk.key --file message.txt --policy "department::finance" --ciphertext signed.enc --aes-bits 192 --ml-dsa 65
npx @wanthinnn/pq-cp-abe --decrypt --verify --user-key signed-user.key --verification-key signed_ml-dsa_pk.key --ciphertext signed.enc --output verified.txt
~~~

| Flag | Meaning |
| --- | --- |
| `--with-signing-keys` | Generate additional ML-DSA keys during `setup` |
| `--sign` | Sign data before encryption |
| `--verify` | Require signature verification when decrypting |
| `--ml-dsa 44/65/87` | Signing parameter set (default 87) |
| `--aes-bits 128/192/256` | AES-GCM size (default 256) |
| `--scheme` | covercrypt (default), ac17 or tkn20 |
| `--config` / `--mode` | CoverCrypt setup config and encapsulation mode |

Legacy `--pqc` and `setup-pqc`/`encrypt-pqc`/`decrypt-pqc` remain accepted for compatibility. `--pqc` refers to the optional ML-DSA signature path, **not** CoverCrypt's PQ KEM mode.

## Run from repository source

The npm package is **built from source WASM artifacts**, not by directly running native C++ through Node.js:

~~~sh
# From repository root, with Emscripten activated
make wasm -j8
make wasm-test -j8
node bindings/wasm/cli.mjs --test
~~~

See the [WASM build instructions](../../../bindings/wasm/README.md) for Emscripten (7.0.0+), Rust nightly + rust-src, Go and host-specific toolchains. `make wasm` builds the JS/WASM output to `lib/wasm/`. Its production runtime contains the Emscripten binary, the separate TKN20 Go WASM module and matching `wasm_exec.js`.

### Packaging

The production publishing pipeline is described in [release maintenance](../../project/releases.md). The npm packaging helper downloads/validates the versioned WASM release ZIP, verifies its SHA-256 manifest, stages the npm package, installs the tarball in a temporary test project, then runs SDK and CLI tests.

Relevant files:

- [`bindings/npm/pack_release.py`](../../../bindings/npm/pack_release.py)
- [`.github/workflows/publish-npm.yml`](../../../.github/workflows/publish-npm.yml)
- [`scripts/package-release.py`](../../../scripts/package-release.py)
- [`Makefile.wasm`](../../../Makefile.wasm)

## API file operations are different from CLI paths

`api.setupFiles`, `api.encryptFile` and `api.decryptFile` from JavaScript operate on the **Emscripten virtual filesystem**. Transfer data with `api.native.FS.writeFile` / `readFile`. The Node CLI explicitly bridges filesystem data to/from real host paths.

For JS modules and types see the [WASM API reference](api.md); for the native executable see [the native CLI guide](../../native/cli.md).
