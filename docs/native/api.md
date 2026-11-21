---
icon: lucide/code-xml
---

# Native C and C++ API

Use the native API when your application links the SDK directly. C and C++
call the same public C ABI. Include `hybrid_pq_cp_abe/hybrid-pq-cp-abe.h` and
link a library built for your platform. [Native build guide](build.md)

## Download a prebuilt native SDK

For most users, downloading a prebuilt SDK is faster than building the native library from source.

Choose the package for your platform. These links point directly to the archive, so the download starts without opening the GitHub Releases page.

<div class="pq-download-grid" markdown>

[:lucide-download: **Windows x86-64**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE/releases/latest){ .md-button .pq-download-button data-platform="windows" data-arch="x86_64" }

[:lucide-download: **Linux x86-64**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE/releases/latest){ .md-button .pq-download-button data-platform="linux" data-arch="x86_64" }

[:lucide-download: **macOS 12+ · Apple Silicon**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE/releases/latest){ .md-button .pq-download-button data-platform="macos" data-arch="arm64" }

[:lucide-download: **macOS 12+ · Intel**](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE/releases/latest){ .md-button .pq-download-button data-platform="macos" data-arch="x86_64" }

</div>

Extract the archive and use its `include/` directory for headers and `lib/` directory for linking. Keep the headers and native libraries from the **same release**.

!!! note
    The download buttons resolve the latest stable GitHub Release at page load and link to its real versioned archive, for example `libhybrid-pq-cp-abe_linux_x86_64_v6.1.0.zip`. If JavaScript is unavailable, the buttons fall back to the latest Release page. The macOS builds target macOS 12.0 or later.

If a suitable prebuilt archive is not available for your OS or architecture, follow the [build-from-source guide](build.md).

## Encrypt and decrypt a file

This example uses the current native API to create an AC17 authority, issue a key for
`admin`, and encrypt a file under that policy. Run it in a fresh working
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
        !succeeded(hybrid_cpabe_encrypt_with_scheme("authority_pk.key", "message.txt",
                                                    "admin", "message.enc", scheme), "encrypt") ||
        !succeeded(hybrid_cpabe_decrypt("user.key", "message.enc", "recovered.txt"), "decrypt"))
        return 1;

    return 0;
}
```

### Compile and run on Linux

`SDK` is a shell variable holding the **full path to the SDK folder you extracted**.
Choose the folder that contains both `include/` and `lib/`. For example, after
extracting the Linux archive into your Downloads folder, the layout is:

```text
/home/alex/Downloads/libhybrid-pq-cp-abe_linux_x86_64_vX.Y.Z/
├── include/
│   └── hybrid_pq_cp_abe/
│       └── hybrid-pq-cp-abe.h
└── lib/
    └── libhybrid-pq-cp-abe.so
```

For this example, set the variable as follows. `$HOME` expands to your home
directory, such as `/home/alex`. Adjust the folder name and version to match
the archive you actually extracted:

```sh
SDK="$HOME/Downloads/libhybrid-pq-cp-abe_linux_x86_64_vX.Y.Z"
```

Create a separate folder for the example, then save the C code above as
`demo.c` inside it:

```sh
mkdir -p "$HOME/pq-cp-abe-demo"
cd "$HOME/pq-cp-abe-demo"
```

Run the following commands **from that folder, in the same terminal** where you
set `SDK`. The compiler uses `$SDK/include` for headers and `$SDK/lib` for the
native library; `demo.c` is read from your current working directory.

```sh
gcc -std=c11 -Wall -Wextra -I"$SDK/include" demo.c -L"$SDK/lib" -lhybrid-pq-cp-abe -o demo
printf '%s\n' 'hello from the native SDK' > message.txt
LD_LIBRARY_PATH="$SDK/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ./demo
cmp message.txt recovered.txt
```

The example creates its keys, `message.txt`, `message.enc` and `recovered.txt`
in the working folder. `LD_LIBRARY_PATH` lets the program find the SDK's shared
library at runtime. If `cmp` prints nothing and exits successfully, the recovered
file matches the original byte for byte.

If you built from repository source with `make shared`, set `SDK` to the full
path of that checkout instead, for example `SDK="$HOME/projects/Hybrid-PQ-CP-ABE"`.
The checkout must contain the built shared library under `lib/`.

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
