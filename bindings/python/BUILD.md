# Build the Python SDK

The Python package wraps the native library through `ctypes`. Building Python
support means building or obtaining the native runtime, then installing the
Python package. It does not compile or execute WebAssembly.

Run the commands below from the repository root.

## Prerequisites

- Python 3.10 or newer, with pip.
- The compiler, Rust, Go, CMake and GNU Make toolchains described in the
  [native build guide](../../docs/native/build.md).
- A virtual environment is recommended for the Python tools and installation.

On Windows, build the native library from an activated **x64 Native Tools Command
Prompt for VS 2022**, with the other tools on `PATH`. Follow the native guide's
Windows setup rather than running the compiler from an unconfigured terminal.

## Build the native runtime

```sh
make deps -j8
make -j8
```

The resulting shared library is placed in the repository's `lib/` directory:

| Platform | Runtime required by the Python loader |
| --- | --- |
| Windows x64 | `libhybrid-pq-cp-abe.dll` and `libcpabe_tkn20.dll` |
| Linux x64 | `libhybrid-pq-cp-abe.so` |
| macOS Intel / Apple Silicon | `libhybrid-pq-cp-abe.dylib` for the current architecture |

Use `make test -j8` to run the native test suite when needed. It is separate from
building or installing the Python package.

## Install the local Python source

```sh
python -m pip install -e ./bindings/python
python -c "import pq_cp_abe as abe; print(abe.__version__, abe.get_version()); print(abe.__file__); print(abe.native._name)"
```

This editable installation uses local source and does not require a PyPI release.
Changes to Python code take effect without reinstalling, but changes to C++, Rust
or Go require rebuilding the native library and restarting the Python process.

The loader first looks in `bindings/python/pq_cp_abe/_libs/`, then falls back to
the repository's `lib/`. An older runtime staged in `_libs/` takes precedence over
a newly built runtime in `lib/`; inspect the printed native path before testing.
On Windows, keep the TKN20 runtime DLL beside the core DLL.

To run the installed package's cryptographic self-test:

```sh
python -m pq_cp_abe --test
```

Continue with the [Python SDK guide](../../docs/bindings/python/README.md) for
typed objects, policies and encryption examples.

## Package a platform wheel

The existing wheel pipeline uses **published GitHub Release native SDKs** as its
inputs. The version in the repository's `VERSION` file must already have a
matching GitHub Release and `SHA256SUMS.txt`. This does not require publishing
the Python package to PyPI.

```sh
python -m pip install --upgrade build
```

Stage the runtime for the current machine with one of these commands:

| Runner | Staging command |
| --- | --- |
| Windows x64 | `python bindings/python/stage_native.py --platform windows --arch x86_64` |
| Linux x64 | `python bindings/python/stage_native.py --platform linux --arch x86_64` |
| macOS Intel | `python bindings/python/stage_native.py --platform macos --arch x86_64` |
| macOS Apple Silicon | `python bindings/python/stage_native.py --platform macos --arch arm64` |

The script downloads the matching SDK, checks its SHA-256 digest and stages the
native binaries and required license notices. It does not build the native SDK
from source. If the native release is not published yet, use the editable source
workflow above instead.

After staging:

```sh
python -m build --wheel bindings/python
python bindings/python/verify_wheel.py --wheel-dir bindings/python/dist
```

Wheels are written to `bindings/python/dist/`. The verifier tests an isolated
installation, including native loading, encryption round trips and the CLI.
These wheels contain platform-specific binaries; they must not be relabeled as
universal `py3-none-any` wheels.

For distributable Linux/macOS wheels, follow the platform repair and compatibility
steps in the [Python wheel workflow](../../.github/workflows/publish-pypi.yml),
including `auditwheel` or `delocate` as applicable. A locally working wheel alone
does not prove it is portable to every OS version or machine.
