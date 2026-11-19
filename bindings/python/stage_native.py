#!/usr/bin/env python3
"""Stage native binaries from a verified GitHub Release, never a local build.

The root VERSION selects the immutable release tag. SHA256SUMS.txt must match
the exact archive bytes before any runtime file is installed into the package.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import sysconfig
import tempfile
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = Path(__file__).resolve().parent / "pq_cp_abe" / "_libs"
RELEASE_BASE = "https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/download"
TARGETS = {("windows", "x86_64"), ("linux", "x86_64"),
           ("macos", "x86_64"), ("macos", "arm64")}
EXT = {"windows": "dll", "linux": "so", "macos": "dylib"}
SYSTEM = {"windows": "Windows", "linux": "Linux", "macos": "Darwin"}

def normalized_arch():
    machine = (platform.machine() or os.getenv("PROCESSOR_ARCHITECTURE")
               or sysconfig.get_platform().split("-")[-1]).lower()
    return {"amd64": "x86_64", "aarch64": "arm64", "x64": "x86_64"}.get(machine, machine)

def release_version():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    import re
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[a-zA-Z0-9.+-]*)?", version):
        raise ValueError(f"Unsafe or invalid root VERSION: {version!r}")
    return version

def download(url, max_bytes):
    req = Request(url, headers={"User-Agent": "pq-cp-abe-wheel-builder"})
    with urlopen(req, timeout=120) as response:
        content = response.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError(f"Release asset exceeds maximum size: {url}")
    return content

def checksums(data):
    result = {}
    for line in data.decode("utf-8-sig").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        name = name.lstrip("*")
        if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            raise ValueError(f"Invalid checksum for {name!r}")
        if name in result:
            raise ValueError(f"Duplicate checksum for {name!r}")
        result[name] = digest.lower()
    return result

def stage(platform_name, arch):
    if (platform_name, arch) not in TARGETS:
        raise ValueError(f"Unsupported platform/architecture: {platform_name}/{arch}")
    if platform.system() != SYSTEM[platform_name] or normalized_arch() != arch:
        raise RuntimeError(f"Runner mismatch: expected {platform_name}/{arch}, "
                           f"actual {platform.system()}/{normalized_arch()}")

    version = release_version()
    label = "win" if platform_name == "windows" else platform_name
    archive_name = f"libhybrid-pq-cp-abe_{label}_{arch}_v{version}.zip"
    base = f"{RELEASE_BASE}/v{version}"
    expected = checksums(download(f"{base}/SHA256SUMS.txt", 200_000))
    if archive_name not in expected:
        raise ValueError(f"SHA256SUMS.txt does not include {archive_name}")

    raw = download(f"{base}/{archive_name}", 500_000_000)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected[archive_name]:
        raise ValueError(f"SHA-256 mismatch for {archive_name}")
    print(f"Verified SHA-256: {archive_name} ({digest})", flush=True)

    core = f"libhybrid-pq-cp-abe.{EXT[platform_name]}"
    required = [core] + (["libcpabe_tkn20.dll"] if platform_name == "windows" else [])
    root_name = archive_name.removesuffix(".zip")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = {}
        for file in archive.infolist():
            # Existing release archive structure is <archive-stem>/lib/<filename>.
            path = PurePosixPath(file.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in file.filename:
                raise ValueError(f"Unsafe ZIP entry: {file.filename}")
            if len(path.parts) == 3 and path.parts[:2] == (root_name, "lib") and path.name in required:
                if path.name in entries:
                    raise ValueError(f"Duplicate runtime: {path.name}")
                entries[path.name] = file
        missing = set(required) - set(entries)
        if missing:
            raise ValueError(f"Missing runtime files in verified GitHub release: {sorted(missing)}")

        # All-or-nothing stage: validate before replacing the existing binaries.
        PACKAGE.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="stage-pq-abe-") as tmp:
            tmpdir = Path(tmp)
            for name in required:
                info = entries[name]
                if info.file_size <= 0 or info.file_size > 250_000_000:
                    raise ValueError(f"Invalid runtime size: {name}")
                with archive.open(info) as source, (tmpdir / name).open("wb") as dest:
                    shutil.copyfileobj(source, dest)
            for old in PACKAGE.iterdir():
                if old.suffix.lower() in (".dll", ".so", ".dylib") and old.is_file():
                    old.unlink()
            for name in required:
                shutil.move(str(tmpdir / name), str(PACKAGE / name))

    for name in required:
        print(f"Staged GitHub Release v{version}: {PACKAGE / name}")
    return [PACKAGE / name for name in required]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=sorted(EXT))
    parser.add_argument("--arch", required=True, choices=["x86_64", "arm64"])
    args = parser.parse_args()
    stage(args.platform, args.arch)

if __name__ == "__main__":
    main()
