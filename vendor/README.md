# Vendored dependencies

These directories contain source snapshots required to build Hybrid-CP-ABE-Library without separately cloning its primary native dependencies.

| Directory | Upstream | Pinned revision |
| --- | --- | --- |
| `librabe-ffi/` | WanThinnn/librabe-ffi | `ff828d13a635042c9569cfb29117f299b553f946` |
| `cryptopp/` | weidai11/cryptopp | `5873a73a231c95771f5bbf3466a484952fb22780` |
| `liboqs/` | open-quantum-safe/liboqs | `e1f480f382d9443c4412133b55948374c77a5c21` |
| `circl/` | cloudflare/circl | `v1.6.4` / `901199c7d4fcefc8c43e8ad46397439ccd3a0ed0` |
| `cover_crypt/` | Cosmian/cover_crypt | see its `UPSTREAM.md` |

Each upstream source keeps its original license/notices. Project-owned integration code is kept outside upstream source directories.
