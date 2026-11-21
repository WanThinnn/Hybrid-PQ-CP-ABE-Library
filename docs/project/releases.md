# Release maintenance

Pushing a `v*` tag or publishing a GitHub Release builds and tests Windows x64
(MSVC), Linux x86_64, macOS Intel, and macOS Apple Silicon on native runners.
A separate Linux job builds the WebAssembly SDK and runs the Node.js smoke
suite against the extracted ZIP. The release attaches all four native SDK
ZIPs, the Linux Vault ZIP, the WASM ZIP, and `SHA256SUMS.txt` after every check
passes. A manual workflow run produces downloadable Actions artifacts.

After the GitHub Release is available, manually run **Build Python Wheels**
from a ref whose `VERSION` matches that release. With `publish=false`, the
workflow builds and tests all four wheels and keeps them as Actions artifacts.
With `publish=true`, it also attaches the verified `.whl` files to the GitHub
Release and publishes them to PyPI.

The workflow must be committed before creating the tag/release. Historical
prebuilt files tracked by Git LFS are not used. Use
`./scripts/release.sh 6.0.1 --dry-run` to preview the release assets.
After committing the release changes, `./scripts/release.sh 6.0.1` checks the
root `VERSION` file and release notes, asks before pushing, then pushes the branch and tag.
The public version header is generated during builds and need not exist when tagging.
By default it refuses to replace an existing tag. To retry an unpublished release
after fixing CI, run `./scripts/release.sh 6.0.1 --replace-tag`. After confirmation,
it pushes the branch, removes the existing tag from origin and locally, then
creates and pushes a new tag at the current commit. Remote deletion stops if the
tag changed since preflight. Use `--replace-tag --dry-run` to preview without changes.
For releases already distributed to users, publish a new version instead.

## Acknowledgements
Special thanks to [Aya0wind](https://github.com/Aya0wind) for Rabe-ffi, [Cloudflare](https://github.com/cloudflare/circl) for CIRCL TKN20, [Open Quantum Safe](https://github.com/open-quantum-safe) for `liboqs`, [CryptoPP](https://github.com/weidai11/cryptopp), and [Cosmian](https://github.com/Cosmian/cover_crypt) for CoverCrypt. CoverCrypt attribution and its BUSL-1.1 license are retained in `vendor/cover_crypt/`.
