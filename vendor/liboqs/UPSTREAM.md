# Upstream

- Project: liboqs
- Repository: https://github.com/open-quantum-safe/liboqs
- Vendored commit: `f822b059350af22adad99ef6b09a18819bcd49ed`
- Upstream: Open Quantum Safe project
- License: see `LICENSE.txt`

The upstream license and third-party notices remain part of the vendored source tree.

Local integration patch: `.CMake/compiler_opts.cmake` honors an explicit
`CMAKE_MSVC_RUNTIME_LIBRARY` instead of forcing `/MT`. The Windows dependency
builder selects `MultiThreadedDLL` (`/MD`) to match the native C++ library.

MSVC builds also use UTF-8 source encoding and skip generic ASM language
discovery. The optimization-barrier limitation is reported once per CMake
configuration; a private build definition avoids repeating it for every object.
The fallback implementation and warnings for external consumers are unchanged.
