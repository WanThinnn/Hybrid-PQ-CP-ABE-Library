# PQ-CP-ABE Documentation

Encrypt data under an attribute policy from an application, a command line,
or a Vault mount. Set up an authority, issue a user key, then encrypt using
a policy that describes which attributes may decrypt the ciphertext.

| Start here | Use it when |
| --- | --- |
| [Python SDK](bindings/python/README.md) | You want Python classes, functions, or the pip CLI. |
| [JavaScript and WebAssembly SDK](bindings/wasm/README.md) | You want to use Node.js, TypeScript, or a browser. |
| [Native C and C++ API](native/api.md) | Your application links the native library directly. |
| [Native CLI](native/cli.md) | You want to encrypt and decrypt files from a terminal. |
| [HashiCorp Vault](integrations/vault.md) | Vault manages your authority and key issuance. |

AC17 and TKN20 use classical ABE. CoverCrypt supports ML-KEM-768 for
post-quantum key encapsulation. ML-DSA adds an optional signature layer.
[Schemes and access policies](architecture/README.md) · [Parameters and ciphertext format](native/parameters.md)

[Build from source](native/build.md) · [Benchmarks](project/benchmarks.md) · [Releases](project/releases.md)
