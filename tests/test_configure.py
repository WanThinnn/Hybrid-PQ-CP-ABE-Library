"""Exercise configure without installing packages or accessing the network."""
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SHELL = shutil.which("sh")
if os.name == "nt":
    candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
    if candidate.is_file():
        SHELL = str(candidate)


@unittest.skipUnless(SHELL, "POSIX shell required for configure shell tests")
class ConfigureTests(unittest.TestCase):
    def test_wasm_install_provisions_sdk_and_rust_without_network(self):
        with tempfile.TemporaryDirectory(prefix="wasm configure ") as directory:
            path = Path(directory)
            (path / "configure").write_bytes((ROOT / "configure").read_bytes())
            module = path / "bindings/tkn20"
            module.mkdir(parents=True)
            (module / "go.mod").write_bytes((ROOT / "bindings/tkn20/go.mod").read_bytes())
            commands = path / "bin"
            commands.mkdir()
            def posix(file):
                if os.name == "nt":
                    return subprocess.check_output([SHELL, "-c", 'cygpath -u "$1"',
                                                    "test", str(file)], text=True).strip()
                return str(file)
            fixture = posix(path)
            sdk = path / "sdk-template"
            sdk.mkdir()
            (sdk / "emsdk").write_text('''#!/bin/sh
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$1" in
  install)
    echo "emsdk $*" >> "$CONFIGURE_TEST_TRACE"
    mkdir -p "$dir/bin"
    for tool in emcc em++ emar emranlib emcmake emcc.exe; do
      cp "$CONFIGURE_TEST_HOME/emtool" "$dir/bin/$tool"
    done ;;
  activate) echo "emsdk $*" >> "$CONFIGURE_TEST_TRACE" ;;
  construct_env) printf 'export PATH="%s/bin:$PATH"\\nexport EMSDK="%s"\\n' "$dir" "$dir" ;;
esac
''', newline="\n")
            (sdk / "emsdk").chmod(0o755)
            (path / "emtool").write_text('#!/bin/sh\necho "Emscripten 7.0.0"\n', newline="\n")
            (path / "emtool").chmod(0o755)
            stub = '''#!/bin/sh
name=${0##*/}
case "$name" in
  uname) if [ "${1:-}" = -m ]; then echo x86_64; else echo "${CONFIGURE_TEST_OS:-MINGW64_NT-10.0}"; fi ;;
  go) echo 'go version go1.26.0 windows/amd64' ;;
  make) echo 'GNU Make 4.4' ;;
  node) echo v24.0.0 ;;
  rustup)
    case "$1" in
      run) test -f "$CONFIGURE_TEST_HOME/rust-ready" ;;
      component) if [ -f "$CONFIGURE_TEST_HOME/rust-ready" ]; then echo rust-src; fi ;;
      toolchain) echo "rustup $*" >> "$CONFIGURE_TEST_TRACE"; touch "$CONFIGURE_TEST_HOME/rust-ready" ;;
    esac ;;
  git)
    echo "git $*" >> "$CONFIGURE_TEST_TRACE"
    for target; do :; done
    cp -R "$CONFIGURE_TEST_HOME/sdk-template" "$target" ;;
  powershell.exe) exit 0 ;;
  pacman) echo "pacman $*" >> "$CONFIGURE_TEST_TRACE" ;;
  *) echo test-tool ;;
esac
'''
            for name in ("uname", "go", "make", "node", "rustup", "git", "powershell.exe",
                         "pacman", "cmake", "ninja", "gcc", "g++", "gcc-ar", "curl",
                         "cargo", "rustc", "xcode-select", "brew"):
                (commands / name).write_text(stub, newline="\n")
                (commands / name).chmod(0o755)
            # Delegate Python and cygpath to real tools; all installers are stubs.
            (commands / "python3").write_text('#!/bin/sh\nexec ' + shlex.quote(posix(sys.executable)) + ' "$@"\n', newline="\n")
            (commands / "python3").chmod(0o755)
            env = dict(os.environ, CONFIGURE_TEST_PATH=fixture + "/bin:/usr/bin:/bin",
                       CONFIGURE_TEST_HOME=fixture, CONFIGURE_TEST_FILE=str(path / "configure"),
                       CONFIGURE_TEST_TRACE=fixture + "/installed", EMSDK="", MSYSTEM="MINGW64",
                       HCPABE_CONFIGURE_DISCOVER_PATHS="0")
            if os.name != "nt":
                (commands / "cygpath").write_text('#!/bin/sh\nprintf "%s\\n" "$2"\n', newline="\n")
                (commands / "cygpath").chmod(0o755)
                env.update(USERPROFILE=fixture, PROGRAMFILES=fixture)
            result = self.run_configure("--wasm", env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("[MISSING] emcc", result.stdout)
            self.assertFalse((path / "installed").exists())
            result = self.run_configure("--wasm", "--install", env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            trace = (path / "installed").read_text()
            self.assertIn("emsdk install 7.0.0", trace)
            self.assertIn("emsdk activate 7.0.0", trace)
            self.assertIn("rustup toolchain install nightly-x86_64-pc-windows-msvc", trace)
            self.assertIn("Ready: make wasm", result.stdout)
            self.assertTrue((path / "build/tools/activate-wasm.sh").is_file())
            self.assertTrue((path / "build/tools/activate-wasm.cmd").is_file())
            self.assertNotIn(b"\r", (path / "build/tools/activate-wasm.sh").read_bytes())
            # A compatible active SDK must be reused without cloning/installing again.
            reuse_env = dict(env, EMSDK=fixture + "/build/tools/emsdk",
                             CONFIGURE_TEST_PATH=fixture + "/build/tools/emsdk/bin:" + env["CONFIGURE_TEST_PATH"])
            result = self.run_configure("--wasm", "--install", env=reuse_env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(trace, (path / "installed").read_text())
            result = subprocess.run([SHELL, "-c",
                                     'export PATH="$CONFIGURE_TEST_PATH"; . "$CONFIGURE_TEST_HOME/build/tools/activate-wasm.sh"; emcc --version'],
                                    env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Emscripten 7.0.0", result.stdout)
            for system in ("Linux", "Darwin"):
                with self.subTest(system=system):
                    (path / "installed").unlink()
                    (path / "rust-ready").unlink()
                    shutil.rmtree(path / "build/tools/emsdk")
                    result = self.run_configure("--wasm", "--install",
                                                env=dict(env, CONFIGURE_TEST_OS=system))
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    trace = (path / "installed").read_text()
                    self.assertIn("emsdk install 7.0.0", trace)
                    self.assertIn("rustup toolchain install nightly --profile minimal --component rust-src", trace)

    def run_configure(self, *arguments, env=None):
        command = [SHELL, str(ROOT / "configure"), *arguments]
        if env and "CONFIGURE_TEST_PATH" in env:
            # Set POSIX PATH inside the shell: Windows converts a PATH supplied
            # through CreateProcess before MSYS/Git Bash starts.
            command = [SHELL, "-c", 'export PATH="$CONFIGURE_TEST_PATH" HOME="$CONFIGURE_TEST_HOME"; file=$1; shift; exec /bin/sh "$file" "$@"',
                       "configure-test", env.get("CONFIGURE_TEST_FILE", str(ROOT / "configure")), *arguments]
        return subprocess.run(command,
                              cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)

    def test_help_and_invalid_options_do_not_need_a_toolchain(self):
        result = self.run_configure("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--install", result.stdout)
        self.assertIn("--wasm", result.stdout)
        result = self.run_configure("--unknown")
        self.assertEqual(result.returncode, 2)

    def test_read_only_checks_and_minimum_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            commands = path / "bin"
            commands.mkdir()
            stub = """#!/bin/sh
name=${0##*/}
case "$name" in
  uname)
    if [ "${1:-}" = -m ]; then echo "${CONFIGURE_TEST_ARCH:-x86_64}"
    else echo "${CONFIGURE_TEST_OS:-Linux}"; fi ;;
  go) echo "go version go${CONFIGURE_TEST_GO:-1.24.0} test/amd64" ;;
  make) echo "GNU Make ${CONFIGURE_TEST_MAKE:-4.4}" ;;
  emcc|em++) echo "emcc Emscripten ${CONFIGURE_TEST_EMSDK:-7.0.0}" ;;
  node) echo "v${CONFIGURE_TEST_NODE:-18.0.0}" ;;
  rustup)
    if [ "${1:-}" = run ] && [ -n "${CONFIGURE_TEST_RUST:-}" ] &&
        [ "$2" != "$CONFIGURE_TEST_RUST" ]; then exit 1; fi
    if [ "${1:-}" = component ]; then echo "${CONFIGURE_TEST_RUST_SRC:-rust-src}"
    else echo test-rustup; fi ;;
  powershell.exe) exit "${CONFIGURE_TEST_VS_STATUS:-0}" ;;
  brew) echo /nonexistent-configure-test ;;
  curl|apt-get|sudo)
    if [ "${1:-}" != --version ]; then echo unexpected-install >> "$CONFIGURE_TEST_TRACE"; exit 99; fi
    echo test-tool ;;
  *) echo test-tool ;;
esac
"""
            for name in ("uname", "go", "make", "brew", "cmake", "gcc", "g++", "gcc-ar",
                         "clang++", "git", "curl", "python3", "cargo", "rustc",
                         "rustup", "apt-get", "sudo", "emcc", "em++", "emar", "emranlib",
                         "emcmake", "node", "cygpath", "ninja", "emcc.exe", "powershell.exe"):
                file = commands / name
                file.write_text(stub, encoding="utf-8", newline="\n")
                file.chmod(0o755)
            if os.name == "nt":
                posix_path = subprocess.check_output(
                    [SHELL, "-c", 'cygpath -u "$1"', "test", str(path)], text=True).strip()
            else:
                posix_path = str(path)
            env = dict(os.environ, CONFIGURE_TEST_PATH=posix_path + "/bin:/usr/bin:/bin",
                       CONFIGURE_TEST_HOME=posix_path, CONFIGURE_TEST_TRACE=posix_path + "/installed",
                       HCPABE_CONFIGURE_DISCOVER_PATHS="0")
            # Simulate a modern host tool found by auto-discovery (as on macOS
            # runners). Explicit test PATH must still expose the old Go stub.
            auto = path / ".cargo/bin"
            auto.mkdir(parents=True)
            (auto / "go").write_text('#!/bin/sh\necho "go version go9.99.0 test/amd64"\n', newline="\n")
            (auto / "go").chmod(0o755)
            env["CONFIGURE_TEST_EMSDK"] = "3.1.6"
            for system in ("Linux", "Darwin"):
                with self.subTest(system=system):
                    env["CONFIGURE_TEST_OS"] = system
                    result = self.run_configure(env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Ready:", result.stdout)
                    self.assertNotIn("Emscripten", result.stdout)
            result = self.run_configure("--wasm", env=dict(env, CONFIGURE_TEST_OS="FreeBSD"))
            self.assertEqual(result.returncode, 1)
            self.assertIn("requires Linux/WSL, macOS, or Windows MSYS2", result.stderr)

            env["CONFIGURE_TEST_OS"] = "Linux"
            go_mod = (ROOT / "bindings/tkn20/go.mod").read_text(encoding="utf-8")
            wasm_go = next(line.split()[1] for line in go_mod.splitlines() if line.startswith("go "))
            env["CONFIGURE_TEST_GO"] = wasm_go
            result = self.run_configure("--wasm", env=env)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Emscripten SDK >= 7.0.0", result.stdout)
            env["CONFIGURE_TEST_EMSDK"] = "7.0.0"
            result = self.run_configure("--wasm", env=env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Ready: make wasm", result.stdout)
            self.assertNotIn("[OK] gcc", result.stdout)
            for system, arch in (("Darwin", "x86_64"), ("Darwin", "arm64"), ("MSYS_NT-10.0", "x86_64")):
                with self.subTest(wasm_system=system, arch=arch):
                    rust = "nightly-x86_64-pc-windows-msvc" if system.startswith("MSYS") else "nightly"
                    host_env = dict(env, CONFIGURE_TEST_OS=system, CONFIGURE_TEST_ARCH=arch,
                                    CONFIGURE_TEST_RUST=rust)
                    result = self.run_configure("--wasm", env=host_env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f"WebAssembly ({system} {arch})", result.stdout)
                    self.assertIn(f"[OK] Rust {rust}", result.stdout)
                    if system.startswith("MSYS"):
                        result = self.run_configure("--wasm", env=dict(host_env, CONFIGURE_TEST_VS_STATUS="1"))
                        self.assertEqual(result.returncode, 1)
                        self.assertIn("Visual Studio C++ Build Tools", result.stdout)
            for variable, version, expected in (
                ("CONFIGURE_TEST_GO", "1.24.0", f"Go >= {wasm_go}"),
                ("CONFIGURE_TEST_NODE", "16.0.0", "Node.js >= 18"),
                ("CONFIGURE_TEST_RUST_SRC", "rustfmt", "Rust nightly + rust-src"),
            ):
                with self.subTest(wasm_check=variable):
                    result = self.run_configure("--wasm", env=dict(env, **{variable: version}))
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(expected, result.stdout)

            env["CONFIGURE_TEST_GO"] = "1.23.9"
            result = self.run_configure(env=env)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("Go >= 1.24", result.stdout)
            env["CONFIGURE_TEST_GO"] = "1.24.0"
            env["CONFIGURE_TEST_MAKE"] = "3.81"
            result = self.run_configure(env=env)
            self.assertEqual(result.returncode, 1)
            self.assertIn("GNU Make >= 4", result.stdout)
            self.assertFalse((path / "installed").exists(), "Check mode tried to install/download")

    def test_install_uses_the_detected_package_manager_with_mocked_tools(self):
        with tempfile.TemporaryDirectory(prefix="configure fixture ") as directory:
            path = Path(directory)
            (path / "configure").write_bytes((ROOT / "configure").read_bytes())
            commands = path / "bin"
            commands.mkdir()
            stub = """#!/bin/sh
name=${0##*/}
case "$name" in
  uname) echo "${CONFIGURE_TEST_OS:-Linux}" ;;
  id) echo 0 ;;
  go) echo 'go version go1.24.0 test/amd64' ;;
  make) echo 'GNU Make 4.4' ;;
  xcode-select) echo /test/CommandLineTools ;;
  apt-get|brew)
    if [ "${1:-}" = --prefix ]; then echo /nonexistent-configure-test; exit 0; fi
    echo "$name $*" >> "$CONFIGURE_TEST_TRACE"
    if [ "${1:-}" = install ]; then
      printf '#!/bin/sh\\necho test-cmake\\n' > "$CONFIGURE_TEST_PATH/cmake"
      /bin/chmod +x "$CONFIGURE_TEST_PATH/cmake"
    fi ;;
  curl) if [ "${1:-}" != --version ]; then echo unexpected-download >> "$CONFIGURE_TEST_TRACE"; exit 99; fi ;;
  *) echo test-tool ;;
esac
"""
            for name in ("uname", "id", "go", "make", "xcode-select", "apt-get", "brew",
                         "gcc", "g++", "gcc-ar", "clang++", "git", "curl", "python3", "cargo", "rustc", "rustup", "tar"):
                file = commands / name
                file.write_text(stub, encoding="utf-8", newline="\n")
                file.chmod(0o755)
            # Keep PATH isolated so an installed host CMake cannot hide the
            # missing-tool scenario. Delegate only basic filesystem utilities.
            for name in ("dirname", "mkdir", "awk"):
                file = commands / name
                executable = f"/bin/{name}" if name == "mkdir" else f"/usr/bin/{name}"
                file.write_text(f'#!/bin/sh\nexec {executable} "$@"\n', encoding="utf-8", newline="\n")
                file.chmod(0o755)
            if os.name == "nt":
                posix = subprocess.check_output([SHELL, "-c", 'cygpath -u "$1"', "test", str(path)], text=True).strip()
            else:
                posix = str(path)
            env = dict(os.environ, CONFIGURE_TEST_PATH=posix + "/bin", CONFIGURE_TEST_HOME=posix,
                       CONFIGURE_TEST_TRACE=posix + "/installed", CONFIGURE_TEST_FILE=str(path / "configure"),
                       HCPABE_CONFIGURE_DISCOVER_PATHS="0")
            auto = path / ".cargo/bin"
            auto.mkdir(parents=True)
            (auto / "cmake").write_text('#!/bin/sh\necho host-cmake\n', newline="\n")
            (auto / "cmake").chmod(0o755)
            for system, manager in (("Linux", "apt-get"), ("Darwin", "brew")):
                with self.subTest(system=system):
                    (commands / "cmake").unlink(missing_ok=True)
                    (path / "installed").unlink(missing_ok=True)
                    env["CONFIGURE_TEST_OS"] = system
                    result = self.run_configure("--install", env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((path / "installed").is_file(),
                                    "Expected the mocked installer to run:\n" + result.stdout + result.stderr)
                    trace = (path / "installed").read_text()
                    self.assertIn(manager + " install", trace)
                    self.assertNotIn("unexpected-download", trace)


if __name__ == "__main__":
    unittest.main()
