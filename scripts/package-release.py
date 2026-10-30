#!/usr/bin/env python3
"""Package native build outputs and verify the extracted CLI and shared library."""

import argparse
import json
import os
from pathlib import Path
import platform as host_platform
import re
import shutil
import subprocess
import tempfile
import zipfile


LIBRARY = "libhybrid-pq-cp-abe"
TARGETS = (("linux", "x86_64"), ("windows", "x86_64"),
           ("macos", "x86_64"), ("macos", "arm64"))


def version_string(value):
    value = value.removeprefix("v")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        raise ValueError(f"Unsafe or empty release version: {value!r}")
    return value


def archive_name(target, arch, version):
    label = "win" if target == "windows" else target
    return f"{LIBRARY}_{label}_{arch}_v{version_string(version)}"


def require_file(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise FileNotFoundError(f"Missing or empty release input: {path}")
    with path.open("rb") as source:
        if source.read(43).startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ValueError(f"LFS pointer is not a built binary: {path}")
    return path


def required_outputs(target):
    if target == "windows":
        core = [f"{LIBRARY}.lib", f"{LIBRARY}.dll", f"{LIBRARY}_dll.lib", "main.exe"]
        deps = ["cryptopp/libcryptopp.lib", "cryptopp/cryptopp.dll", "cryptopp/cryptopp.lib",
                "liboqs/liboqs.lib", "liboqs/liboqs.dll", "liboqs/liboqs_import.lib",
                "rabe/librabe_ffi.lib", "rabe/rabe_ffi.dll",
                "tkn20/libcpabe_tkn20.lib", "tkn20/libcpabe_tkn20.dll",
                "covercrypt/libcovercrypt_ffi.lib"]
    else:
        extension = "dylib" if target == "macos" else "so"
        core = [f"{LIBRARY}.a", f"{LIBRARY}.{extension}", "main"]
        deps = [f"{dep}/{name}.{ext}" for dep, name in (
            ("cryptopp", "libcryptopp"), ("liboqs", "liboqs"),
            ("rabe", "librabe_ffi"), ("tkn20", "libcpabe_tkn20"))
            for ext in ("a", extension)]
        deps.append("covercrypt/libcovercrypt_ffi.a")
    return core, deps


def license_files(source, destination):
    """Retain original license/notices without assigning new third-party terms."""
    for directory, folders, names in os.walk(source):
        folders[:] = [name for name in folders if name not in {".git", "target", "node_modules"}]
        for name in names:
            if name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "UPSTREAM")):
                item = Path(directory) / name
                output = destination / item.relative_to(source)
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, output)


def collect_notices(root, package):
    license_files(root / "vendor", package / "vendor")
    cargo = ["cargo"]
    fingerprint = root / "build/deps/windows/lib/rabe/.fingerprint"
    if os.name == "nt" and fingerprint.is_file():
        recorded = re.search(r"^rust_toolchain=(.+)$", fingerprint.read_text(), re.MULTILINE)
        if recorded:
            cargo.append("+" + recorded[1].strip())
    packages = {}
    for manifest in ("vendor/librabe-ffi/Cargo.toml", "bindings/covercrypt/Cargo.toml"):
        metadata = json.loads(subprocess.check_output(cargo + [
            "metadata", "--format-version", "1", "--locked", "--manifest-path",
            str(root / manifest)], cwd=root, text=True, encoding="utf-8"))
        for dependency in metadata["packages"]:
            packages[dependency["id"]] = dependency
    inventory = []
    for dependency in packages.values():
        source = Path(dependency["manifest_path"]).parent
        destination = package / "licenses/rust" / f"{dependency['name']}-{dependency['version']}"
        # Cargo crates keep license files in their package root or subdirectories.
        license_files(source, destination)
        if dependency.get("license_file"):
            license = source / dependency["license_file"]
            if license.is_file():
                destination.mkdir(parents=True, exist_ok=True)
                shutil.copy2(license, destination / license.name)
        inventory.append({"ecosystem": "rust", "name": dependency["name"],
                          "version": dependency["version"], "license": dependency.get("license")})
    modules = subprocess.check_output(["go", "list", "-m", "-json", "all"],
                                      cwd=root / "bindings/tkn20", text=True, encoding="utf-8")
    decoder = json.JSONDecoder()
    while modules.strip():
        module, offset = decoder.raw_decode(modules.lstrip())
        modules = modules.lstrip()[offset:]
        if module.get("Main"):
            continue
        resolved = module.get("Replace", module)
        if resolved.get("Dir"):
            license_files(Path(resolved["Dir"]), package / "licenses/go" / module["Path"])
        inventory.append({"ecosystem": "go", "name": module["Path"], "version": module.get("Version")})
    (package / "licenses").mkdir(exist_ok=True)
    (package / "licenses/dependencies.json").write_text(
        json.dumps(inventory, indent=2) + "\n", encoding="utf-8")


def stage_package(root, package, target):
    require_file(root / 'include/hybrid_pq_cp_abe/version.h')
    core, dependencies = required_outputs(target)
    build = root / "build/artifacts" / target
    deps = root / "build/deps" / target
    for name in core:
        require_file(build / name)
    for name in dependencies:
        require_file(deps / "lib" / name)
    for name in ("cryptopp/aes.h", "rabe/rabe.h", "liboqs/oqs/oqs.h", "tkn20/cpabe_tkn20.h", "covercrypt/covercrypt_ffi.h"):
        require_file(deps / "include" / name)
    package.mkdir(parents=True)
    shutil.copytree(root / "include", package / "include")
    shutil.copytree(deps / "include", package / "include", dirs_exist_ok=True)
    (package / "lib").mkdir()
    (package / "bin").mkdir()
    for name in core:
        folder = "bin" if name in {"main", "main.exe"} else "lib"
        shutil.copy2(build / name, package / folder / name)
    shutil.copytree(deps / "lib", package / "lib/deps", ignore=shutil.ignore_patterns(".*"))
    if target == "windows":
        for folder in ("lib", "bin"):
            shutil.copy2(deps / "lib/tkn20/libcpabe_tkn20.dll", package / folder)
    for name in ("LICENSE", "NOTICE", "README.md", "VERSION"):
        shutil.copy2(require_file(root / name), package / name)
    (package / "PACKAGE.md").write_text(
        "# Native library package\n\n"
        "Public and dependency headers are in include/. Add include/liboqs to your include paths when using oqs headers.\n"
        "The native static/shared libraries are in lib/, the CLI in bin/, and individual dependency libraries in lib/deps/.\n"
        "Third-party notices are retained under vendor/ and licenses/. Missing license metadata is recorded as null, not relicensed.\n"
        "On Windows, link libhybrid-pq-cp-abe_dll.lib for the DLL or libhybrid-pq-cp-abe.lib for static use. Keep libcpabe_tkn20.dll beside the consuming executable. The MSVC runtime is required.\n"
        "On Linux/macOS, static consumers also link the platform system libraries shown in the repository Makefile; shared consumers configure their library search path.\n",
        encoding="utf-8")


def verify_runtime(archive, target):
    with tempfile.TemporaryDirectory(prefix="verify-", dir=archive.parent) as directory:
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(directory)
        package = Path(directory) / archive.stem
        executable = package / "bin" / ("main.exe" if target == "windows" else "main")
        if target != "windows":
            executable.chmod(0o755)
        subprocess.run([str(executable.resolve()), "version"], cwd=package, check=True)
        extension = {"windows": "dll", "linux": "so", "macos": "dylib"}[target]
        library_path = (package / "lib" / f"{LIBRARY}.{extension}").resolve()
        # Load in a subprocess so Windows releases DLL file handles before cleanup.
        subprocess.run([os.sys.executable, "-c",
            "import ctypes,os,sys; "
            "directory=os.add_dll_directory(os.path.dirname(sys.argv[1])) if os.name=='nt' else None; "
            "lib=ctypes.CDLL(sys.argv[1]); lib.getVersion.restype=ctypes.c_char_p; "
            "assert lib.getVersion(); print('Packaged shared library:',lib.getVersion().decode())",
            str(library_path)], cwd=package, check=True)


def write_archive(package, archive):
    # Cargo/Go packages may carry reproducible Unix-epoch timestamps, which ZIP
    # cannot represent. Clamp those timestamps without altering file contents.
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as zipped:
        for item in sorted(package.rglob("*")):
            if item.is_file():
                zipped.write(item, item.relative_to(package.parent))


def prepare_shared_libraries(package, target):
    if target == "linux":
        # The stable dependency surface drops upstream versioned filenames.
        # Retain the SONAME aliases needed by consumers of those shared libs.
        for library in (package / "lib/deps").rglob("*.so"):
            dynamic = subprocess.check_output(["readelf", "-d", str(library)], text=True)
            soname = re.search(r"\(SONAME\).*\[([^]]+)\]", dynamic)
            if soname and soname[1] != library.name:
                if Path(soname[1]).name != soname[1]:
                    raise ValueError(f"Invalid SONAME: {soname[1]}")
                shutil.copy2(library, library.with_name(soname[1]))
    elif target == "macos":
        # Remove install names pointing into temporary CMake staging folders.
        for library in (package / "lib").rglob("*.dylib"):
            subprocess.run(["install_name_tool", "-id", f"@rpath/{library.name}", str(library)], check=True)
            subprocess.run(["codesign", "--force", "--sign", "-", str(library)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "linux", "macos"))
    parser.add_argument("--arch", choices=("x86_64", "arm64"))
    parser.add_argument("--version")
    parser.add_argument("--verify-assets", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = args.version or (os.environ.get("GITHUB_REF_NAME") if os.environ.get("GITHUB_REF_TYPE") == "tag"
                               else "dev-" + os.environ.get("GITHUB_SHA", "local")[:8])
    version = version_string(version)
    if args.verify_assets:
        expected = {archive_name(target, arch, version) + ".zip" for target, arch in TARGETS}
        actual = {path.name for path in args.verify_assets.glob("*.zip")}
        if actual != expected:
            raise ValueError(f"Release assets mismatch: missing={expected - actual}, unexpected={actual - expected}")
        return
    if (args.platform, args.arch) not in TARGETS:
        parser.error("Specify a supported --platform and --arch")
    arch = {"AMD64": "x86_64", "aarch64": "arm64"}.get(host_platform.machine(), host_platform.machine())
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(host_platform.system())
    if (system, arch) != (args.platform, args.arch):
        raise ValueError(f"Native runner mismatch: {(system, arch)} != {(args.platform, args.arch)}")
    output = root / "build/release"
    output.mkdir(parents=True, exist_ok=True)
    name = archive_name(args.platform, args.arch, version)
    with tempfile.TemporaryDirectory(prefix="stage-", dir=output) as directory:
        package = Path(directory) / name
        stage_package(root, package, args.platform)
        collect_notices(root, package)
        prepare_shared_libraries(package, args.platform)
        archive = output / (name + ".zip")
        write_archive(package, archive)
    verify_runtime(archive, args.platform)
    print(f"Verified release archive: {archive}")


if __name__ == "__main__":
    main()
