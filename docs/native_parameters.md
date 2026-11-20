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

No new flags means legacy behavior. Explicit options select V3 encryption:

```sh
main setup --scheme covercrypt --pqc --ml-dsa 65 keys
main genkey --scheme covercrypt keys/cpabe_msk.key "admin it" user.key
main encrypt --scheme covercrypt --pqc --aes-bits 192 --ml-dsa 65 keys/cpabe_pk.key keys/pqc_sk.key message.bin "admin and it" message.enc
main decrypt --pqc user.key keys/pqc_pk.key message.enc recovered.bin
```

Create the `keys` directory and configure CoverCrypt dimensions before setup.
`--aes-bits` is accepted for encrypt/encrypt_buffer. `--ml-dsa` requires
`--pqc` and setup/setup_buffer/encrypt/encrypt_buffer. Decryption detects parameters.

## Python / WASM integration

The native additions are exported through public `LIB_API` declarations; the
WASM export generator includes them automatically. Python must declare their
ctypes argument/result types, and JavaScript wrappers must marshal integer
parameters and copy/free native buffers. Neither should change legacy wrappers
to call V3 implicitly. New OOP APIs may opt into V3 when configured accordingly.
One native library contains all standalone ML-KEM/ML-DSA variants. CoverCrypt
continues to use a single fixed-768 Rust backend, not extra 512/768 modules.

`make test` includes `tests/cpp/params_test.cpp`: the matrix covers all three ABE
schemes, all AES/ML-DSA combinations, binary/empty messages, file operations,
legacy defaults, parameter tampering, truncation and policy denial.
