# Upstream

- Project: Crypto++
- Repository: https://github.com/weidai11/cryptopp
- Vendored commit: `5873a73a231c95771f5bbf3466a484952fb22780`
- Upstream author/maintainers: Wei Dai and Crypto++ contributors
- License: see `License.txt`

The upstream license and copyright notices are retained unchanged.

Local integration patch: `DoDllPowerUpSelfTest` supplies an expected module MAC
only when FIPS compliance mode is enabled. The ordinary MSVC DLL runs
the algorithm self-tests without requiring the legacy Win32 MAC-generation tool.
The compliance-enabled path retains its integrity check.

The ordinary `/MD` DLL also defines `CRYPTOPP_USE_CRT_ALLOCATORS` to use the
shared CRT's standard allocation functions instead of legacy MSVCRT allocator
discovery. The legacy DLL profile keeps its existing allocator hooks.
