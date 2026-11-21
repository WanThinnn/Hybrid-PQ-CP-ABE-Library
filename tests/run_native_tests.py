"""Run and report each native suite separately on every platform."""

import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument("covercrypt_test", type=Path)
    parser.add_argument("params_test", type=Path)
    args = parser.parse_args()
    cli, covercrypt, params = (path.resolve() for path in (args.cli, args.covercrypt_test, args.params_test))
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, HCPABE_EXEC=str(cli))
    legacy = ([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", r"tests\cpp\run_test.bat"]
              if os.name == "nt" else ["bash", "tests/cpp/run_test.sh"])
    suites = [
        ("CoverCrypt integration", "KEM modes, authority updates, key permissions and the C ABI.",
         [str(covercrypt)], root),
        ("Native cryptography and runtime parameters",
         "AES, ML-DSA and ML-KEM variants, hybrid file and buffer operations, and invalid inputs.",
         [str(params)], params.parent),
        ("CLI help and runtime options", "Command help, parameter flags, and legacy defaults on all schemes.",
         [sys.executable, "tests/test_cli_params.py", str(cli), "-v"], root),
        ("CLI legacy regression", "Setup, key issuance, encryption, decryption, signing and verification.",
         legacy, root),
    ]
    results = []
    divider = "=" * 72
    for number, (name, description, command, cwd) in enumerate(suites, 1):
        print(f"\n{divider}\n[{number}/{len(suites)}] {name}\n{description}\n{divider}", flush=True)
        try:
            status = subprocess.run(command, cwd=cwd, env=env).returncode
        except OSError as exc:
            print(exc, file=sys.stderr)
            status = 1
        results.append((name, status))
        print(f"\n{'PASS' if status == 0 else f'FAIL (exit {status})'}  {name}", flush=True)

    print(f"\n{divider}\nNative test summary\n{divider}")
    for name, status in results:
        print(f"  {'PASS' if status == 0 else 'FAIL'}  {name}")
    failures = sum(status != 0 for _, status in results)
    print(f"\n{len(results) - failures} suites passed, {failures} failed")
    return int(failures != 0)


if __name__ == "__main__":
    sys.exit(main())
