# Native runtime parameters (6.1 API)

This is an additive C ABI. Existing entry points retain their signatures and
defaults, including V2 encryption, AES-256 and ML-DSA-87 signing. New decryptors
read V1/V2/V3. A previous library cannot read V3; use legacy encrypt entry points
when producing data for a previous library.

## Parameters and keys

| Operation | Runtime choices | Default |
| --- | --- | --- |
| AES-GCM primitive / hybrid payload | 128, 192, 256 bits | 256 in parameterized hybrid calls |
| ML-DSA primitive / hybrid signing | 44, 65, 87 parameter sets | 87 in parameterized hybrid calls |
| Standalone ML-KEM | 512, 768, 1024 parameter sets | Explicit argument at the C ABI |
| ML-KEM inside CoverCrypt ABE | Fixed 768 | 768 |

`0` selects 256/87 in the new hybrid APIs only. Invalid selections are rejected;
there is no fallback from an unsupported algorithm. The C primitive APIs take
explicit parameter sets. AES primitives select by key length (16/24/32 bytes).

Standalone `ml_dsa_*` keys are raw bytes. Hybrid setup returns Base64-encoded
ML-DSA key bytes, as do the legacy hybrid functions. Hybrid file keys retain the
existing outer Base64 file encoding. Do not pass a raw standalone secret key to
a hybrid signing call without Base64-encoding it. A key from one ML-DSA parameter
set cannot be reused with another.

## Public entry points

Include `hybrid_pq_cp_abe/crypto-params.h` for the named parameter constants
and public API declarations. It includes the existing umbrella header, which
continues to declare all exports so existing consumers and WASM extraction work.

- `hybrid_cpabe_setupBuffer_with_ml_dsa(..., scheme, ml_dsa_parameter_set)`
- `hybrid_cpabe_setup_with_ml_dsa(path, scheme, ml_dsa_parameter_set)`
- `hybrid_cpabe_setup_with_signing_keys(path, scheme, ml_dsa_parameter_set)`
  writes the signing and verification files with the `ml-dsa` label.
- `hybrid_cpabe_encryptBuffer_with_params(..., scheme, aes_key_bits)`
- `hybrid_cpabe_encrypt_with_params(..., scheme, aes_key_bits)`
- `hybrid_cpabe_encryptBuffer_and_sign_with_params(..., scheme, aes_key_bits, ml_dsa_parameter_set)`
- `hybrid_cpabe_encrypt_and_sign_with_params(..., scheme, aes_key_bits, ml_dsa_parameter_set)`
- `hybrid_cpabe_covercrypt_ml_kem_parameter_set()` returns 768.

The existing `hybrid_cpabe_decryptBuffer`, `hybrid_cpabe_decrypt`,
`hybrid_cpabe_decryptBuffer_and_verify`, and `hybrid_cpabe_decrypt_and_verify`
detect V3 parameters automatically. No decrypt-side algorithm selection or
mutable global configuration is required. Signature verification must use the
`and_verify` APIs; plain decrypt returns the signed payload envelope for signed
ciphertexts, consistent with the legacy API.

Buffer results use `freeBuffer`. On failure, new buffer entry points leave
valid output locations NULL/0, and verification never returns unauthenticated
plaintext. All output pointer/length locations must be distinct. File writers
retain the legacy overwrite semantics. File-based setup may create ABE files
before a later signing-key write fails, as with legacy setup.

## V3 wire format

Integers newly introduced by V3 are little-endian. Header layout:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | Version = 3 |
| 1 | 1 | ABE scheme ID (AC17=0, TKN20=1, CoverCrypt=2) |
| 2 | 1 | AES key bytes (16, 24, 32) |
| 3 | 1 | ML-DSA set (0 = unsigned; otherwise 44, 65, 87) |
| 4 | 12 | Random GCM nonce |
| 16 | 8 | Encrypted ABE seed length |
| 24 | Variable | Encrypted ABE seed |
| Following | Variable | AES-GCM ciphertext with 16-byte tag appended |

ABE protects a fresh 32-byte random seed. The AES key is the first N bytes of
SHA3-256(`"HCPABE-V3-AES" || first_four_header_bytes || seed`), where N is 16,
24 or 32. The complete header, including the encrypted seed, is GCM AAD.
There is no change to the vendor's ABE serialization or cryptographic code.

Signed plaintext envelopes are:
`signature_length:u32 || signature || policy_length:u32 || policy || plaintext`.
ML-DSA signs `"HCPABE-V3-SIGN" || first_four_header_bytes || policy_length:u32 || policy || plaintext`.
This binds the scheme, AES size, signature set, policy and message to the
signature in addition to GCM authentication. V1/V2 legacy processing is unchanged.

## CLI

Encryption uses the legacy format by default. Passing `--aes-bits` or
`--ml-dsa` to the encryption command selects V3.

```sh
pq-cp-abe setup --scheme covercrypt --with-signing-keys --ml-dsa 65 keys
pq-cp-abe genkey --scheme covercrypt keys/cpabe_msk.key "admin it" user.key
pq-cp-abe encrypt --scheme covercrypt --sign --aes-bits 192 --ml-dsa 65 keys/cpabe_pk.key keys/ml-dsa_sk.key message.bin "admin and it" message.enc
pq-cp-abe decrypt --verify user.key keys/ml-dsa_pk.key message.enc recovered.bin
```

Create the `keys` directory and configure CoverCrypt dimensions before setup.
`--aes-bits` is accepted for `encrypt` and `encrypt_buffer`. Use `--ml-dsa` with
`--with-signing-keys` on setup or `--sign` on encryption, including the buffer
variants. Decryption detects parameters.

## Python / WASM integration

Python uses `aes_key_bits` and `ml_dsa_parameter_set`. JavaScript uses
`aesKeyBits` and `mlDsaParameterSet`. These options work on the functional
and object APIs. An explicit encryption parameter selects V3. Calls without
either parameter use the legacy format. [Python SDK](../bindings/python/README.md#object-api) ·
[JavaScript SDK](../bindings/npm/README.md#object-api)

One native library contains the standalone ML-KEM and ML-DSA variants.
CoverCrypt uses ML-KEM-768 for its post-quantum encapsulation component.

`make test` includes `tests/cpp/params_test.cpp`: the matrix covers all three ABE
schemes, all AES/ML-DSA combinations, binary/empty messages, file operations,
legacy defaults, parameter tampering, truncation and policy denial.
