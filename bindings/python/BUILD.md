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

## Prepare one build terminal

**Check-only does not create activation scripts.** If the check passes and the
current terminal already has the tools on `PATH`, continue directly to the build
steps. Do not source/call a missing activation file. If tools are missing, or
configure finds them but your terminal cannot run them, use the install command
to generate activation, then activate in this same terminal. Installation only
adds tools that are missing or too old.

### **Linux / macOS**

Use the same Unix shell for setup, activation, the native build and Python
commands. **Check only:**

```sh
./configure
```

**If the check passes in this configured shell, skip to Build the native runtime.**
If setup is needed, install missing tools and generate activation:

```sh
./configure --install
. ./build/tools/activate.sh
```

### **Windows**

**Start in x64 Native Tools Command Prompt and keep that one cmd session for
setup, activation, the native build and Python commands.** If the tools are not
installed, download Visual Studio or Build Tools from
[Microsoft](https://visualstudio.microsoft.com/downloads/) and select
**Desktop development with C++**, including MSVC x64/x86 tools and a Windows SDK.
Open the x64 Native Tools shortcut from the Start menu and enter the repository
root (`cd /d D:\path\to\Hybrid-PQ-CP-ABE`).

**Check only** (no installation or script generation):

```cmd
powershell.exe -NoProfile -Command ^
    "$text = Get-Content .\configure -Raw;" ^
    "$setup = [scriptblock]::Create(($text -split '(?m)^# WINDOWS CONFIGURE\r?$', 2)[1]);" ^
    "& $setup"
```

**If the check passes and tools are already available in this x64 cmd, skip
to Build the native runtime.** Check-only does not generate `activate.cmd`.
If tools are missing or only discovered inside the configure child process,
use the following command to install missing tools and generate activation:

```cmd
powershell.exe -NoProfile -Command ^
    "$text = Get-Content .\configure -Raw;" ^
    "$setup = [scriptblock]::Create(($text -split '(?m)^# WINDOWS CONFIGURE\r?$', 2)[1]);" ^
    "& $setup -Install"
```

**Activate in the same cmd only after successful install/script generation:**

```cmd
call build\tools\activate.cmd
```

The `^` characters continue each setup command across lines in cmd. PowerShell
runs as a child process and returns to this cmd. Activation adds MSYS2/Make,
Go and Rust while preserving the MSVC linker priority. If using this generated
script, run it in each new build session. See the [native Windows setup](../../docs/native/build.md#windows).

If using a Python virtual environment, activate it in this same terminal before
running the Python commands below (`call .venv\Scripts\activate.bat` on cmd,
or `. .venv/bin/activate` on Unix).

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
