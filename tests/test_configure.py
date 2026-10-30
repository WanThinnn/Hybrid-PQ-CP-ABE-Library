"""Exercise configure without installing packages or accessing the network."""
import os
from pathlib import Path
import shutil
import subprocess
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
  uname) echo "${CONFIGURE_TEST_OS:-Linux}" ;;
  go) echo "go version go${CONFIGURE_TEST_GO:-1.24.0} test/amd64" ;;
  make) echo "GNU Make ${CONFIGURE_TEST_MAKE:-4.4}" ;;
  brew) echo /nonexistent-configure-test ;;
  curl|apt-get|sudo)
    if [ "${1:-}" != --version ]; then echo unexpected-install >> "$CONFIGURE_TEST_TRACE"; exit 99; fi
    echo test-tool ;;
  *) echo test-tool ;;
esac
"""
            for name in ("uname", "go", "make", "brew", "cmake", "gcc", "g++",
                         "clang++", "git", "curl", "python3", "cargo", "rustc",
                         "rustup", "apt-get", "sudo"):
                file = commands / name
                file.write_text(stub, encoding="utf-8", newline="\n")
                file.chmod(0o755)
            if os.name == "nt":
                posix_path = subprocess.check_output(
                    [SHELL, "-c", 'cygpath -u "$1"', "test", str(path)], text=True).strip()
            else:
                posix_path = str(path)
            env = dict(os.environ, CONFIGURE_TEST_PATH=posix_path + "/bin:/usr/bin:/bin",
                       CONFIGURE_TEST_HOME=posix_path, CONFIGURE_TEST_TRACE=posix_path + "/installed")
            for system in ("Linux", "Darwin"):
                with self.subTest(system=system):
                    env["CONFIGURE_TEST_OS"] = system
                    result = self.run_configure(env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Ready:", result.stdout)
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
                         "gcc", "g++", "clang++", "git", "curl", "python3", "cargo", "rustc", "rustup", "tar"):
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
                       CONFIGURE_TEST_TRACE=posix + "/installed", CONFIGURE_TEST_FILE=str(path / "configure"))
            for system, manager in (("Linux", "apt-get"), ("Darwin", "brew")):
                with self.subTest(system=system):
                    (commands / "cmake").unlink(missing_ok=True)
                    (path / "installed").unlink(missing_ok=True)
                    env["CONFIGURE_TEST_OS"] = system
                    result = self.run_configure("--install", env=env)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    trace = (path / "installed").read_text()
                    self.assertIn(manager + " install", trace)
                    self.assertNotIn("unexpected-download", trace)


if __name__ == "__main__":
    unittest.main()
