---
icon: lucide/code-xml
---

# Native C and C++ API

Use the native API when your application links the SDK directly. C and C++
call the same public C ABI. Include `hybrid_pq_cp_abe/hybrid-pq-cp-abe.h` and
link a library built for your platform. [Native build guide](build.md)

## Encrypt and decrypt a file

This example creates an AC17 authority, issues a key for `admin`, and
encrypts a file under that policy using AES-192. Run it in a fresh working
directory. Setup writes `authority_pk.key` and `authority_msk.key`.

Save as `demo.c`.

```c
#include <stdio.h>
#include "hybrid_pq_cp_abe/hybrid-pq-cp-abe.h"

static int succeeded(int status, const char *operation)
{
    if (status == HCPABE_SUCCESS)
        return 1;
    fprintf(stderr, "%s failed (%d): %s\n", operation, status, getErrorMessage(status));
    return 0;
}

int main(void)
{
    const CPABEScheme scheme = CPABE_SCHEME_AC17;
    if (!succeeded(setup_with_scheme("authority", scheme), "setup") ||
        !succeeded(generateSecretKey_with_scheme("authority_msk.key", "admin",
                                                 "user.key", scheme), "keygen") ||
        !succeeded(hybrid_cpabe_encrypt_with_params("authority_pk.key", "message.txt",
                                                    "admin", "message.enc", scheme, 192), "encrypt") ||
        !succeeded(hybrid_cpabe_decrypt("user.key", "message.enc", "recovered.txt"), "decrypt"))
        return 1;

    return 0;
}
```

On Linux, point `SDK` to the extracted native SDK. The same commands work
from a source checkout after `make shared` when `SDK` points to that checkout.

```sh
SDK=/absolute/path/to/sdk
cc -std=c11 -Wall -Wextra -I"$SDK/include" demo.c \
  -L"$SDK/lib" -lhybrid-pq-cp-abe -o demo
printf '%s\n' 'hello from the native SDK' > message.txt
LD_LIBRARY_PATH="$SDK/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ./demo
cmp message.txt recovered.txt
```

On Windows with MSVC, link `libhybrid-pq-cp-abe_dll.lib` and place
`libhybrid-pq-cp-abe.dll` and `libcpabe_tkn20.dll` beside the executable.
Use SDK headers and libraries from the same release.

## Choose the operations you need

| Task | C entry points |
| --- | --- |
| Create an authority and issue a file-based key | `setup_with_scheme`, `generateSecretKey_with_scheme` |
| Create an authority or issue a key in memory | `hybrid_cpabe_setupBuffer_with_scheme`, `hybrid_cpabe_genkeyBuffer_with_scheme` |
| Encrypt with an explicit AES key size | `hybrid_cpabe_encrypt_with_params`, `hybrid_cpabe_encryptBuffer_with_params` |
| Create signing keys and sign or verify files | `hybrid_cpabe_setup_with_signing_keys`, `hybrid_cpabe_encrypt_and_sign_with_params`, `hybrid_cpabe_decrypt_and_verify` |
| Configure CoverCrypt in memory | `hybrid_cpabe_covercrypt_setupBuffer_from_json` |
| Release native output buffers | `freeBuffer` |

For CoverCrypt file setup, set `HCPABE_COVERCRYPT_CONFIG` to the dimensions
JSON path and choose `CPABE_SCHEME_COVERCRYPT`. Decryption detects the
ciphertext's scheme and parameters. Supply a trusted verification key to
the verify API when signature verification is required. [CoverCrypt configuration](cli.md#covercrypt-with-ml-dsa-signatures)

The `_with_params` encryptors emit V3. Use the compatible existing encrypt
functions when an older runtime must read the ciphertext. Release each
library-owned output buffer with `freeBuffer` from the same library.
[Parameter and buffer contracts](parameters.md) · [Public C header](../../include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h)
