# Upstream

- Project: liboqs
- Repository: https://github.com/open-quantum-safe/liboqs
- Vendored commit: `e1f480f382d9443c4412133b55948374c77a5c21`
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
