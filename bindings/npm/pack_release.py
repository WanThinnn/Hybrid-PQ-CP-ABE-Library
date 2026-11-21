#!/usr/bin/env python3
"""Pack the WASM release ZIP and smoke-test the installed npm package."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import zipfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = {
    "lib/wasm/loader.mjs", "lib/wasm/api.mjs", "lib/wasm/loader.d.mts", "lib/wasm/hybrid-pq-cp-abe.mjs",
    "lib/wasm/hybrid-pq-cp-abe.wasm", "lib/wasm/tkn20.wasm",
    "lib/wasm/wasm_exec.js",
    "lib/wasm/api/legacy.mjs", "lib/wasm/api/functional.mjs",
    "lib/wasm/runtime/native.mjs", "lib/wasm/runtime/buffers.mjs",
    "lib/wasm/models/enums.mjs", "lib/wasm/utils/errors.mjs", "lib/wasm/utils/validation.mjs",
    "lib/wasm/utils/encoding.mjs", "lib/wasm/pq_cp_abe.mjs", "lib/wasm/abe/index.mjs", "lib/wasm/abe/base.mjs",
    "lib/wasm/abe/ac17.mjs", "lib/wasm/abe/tkn20.mjs", "lib/wasm/abe/covercrypt.mjs",
    "lib/wasm/primitives/index.mjs", "lib/wasm/primitives/aes_gcm.mjs", "lib/wasm/primitives/ml_dsa.mjs",
    "lib/wasm/primitives/ml_kem.mjs", "lib/wasm/runtime/primitive.mjs",
}
REQUIRED_NOTICES = {
    "LICENSE", "NOTICE", "licenses/go-runtime/LICENSE",
    "vendor/cover_crypt/LICENSE.md",
}


def verify_checksum(archive, manifest):
    pattern = re.compile(r"([0-9a-fA-F]{64}) [ *]" + re.escape(archive.name))
    matches = [match[1].lower() for line in manifest.read_text(encoding="utf-8").splitlines()
               if (match := pattern.fullmatch(line))]
    if len(matches) != 1:
        raise ValueError(f"Expected one SHA-256 entry for {archive.name} in {manifest}")
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != matches[0]:
        raise ValueError(f"SHA-256 mismatch for {archive.name}")


def stage_package(archive, stage, version):
    required = RUNTIME | REQUIRED_NOTICES | {"VERSION"}
    with zipfile.ZipFile(archive) as zipped:
        entries = {}
        for member in zipped.infolist():
            path = PurePosixPath(member.filename)
            if member.is_dir() or path.parts[:1] != (archive.stem,):
                continue
            relative = PurePosixPath(*path.parts[1:])
            name = relative.as_posix()
            if name not in required and relative.parts[:1] not in (("licenses",), ("vendor",)):
                continue
            if (".." in relative.parts or "\\" in name or ":" in name
                    or name in entries or not member.file_size):
                raise ValueError(f"Unsafe, duplicate, or empty ZIP entry: {member.filename}")
            entries[name] = member
        if missing := required - entries.keys():
            raise ValueError(f"Missing WASM release files: {sorted(missing)}")
        if zipped.read(entries.pop("VERSION")).decode("utf-8").strip() != version:
            raise ValueError(f"{archive.name} contains a different VERSION than {version}")
        for name, member in entries.items():
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with zipped.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)

    metadata = json.loads((HERE / "package.json").read_text(encoding="utf-8"))
    metadata["version"] = version
    metadata.pop("private", None)
    (stage / "package.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    shutil.copy2(HERE / "README.md", stage / "README.md")
    cli = stage / "bindings/wasm"
    cli.mkdir(parents=True)
    for source in ("cli.mjs", "selftest.mjs"):
        shutil.copy2(ROOT / "bindings/wasm" / source, cli / source)
    return metadata["name"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="WASM release ZIP (default: build/release/<versioned ZIP>)")
    parser.add_argument("--checksums", type=Path, help="Verify the ZIP against this SHA256SUMS.txt")
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        parser.error(f"VERSION must be an npm version without a leading v: {version!r}")
    archive_name = f"libhybrid-pq-cp-abe_wasm_v{version}.zip"
    archive = args.archive or ROOT / "build/release" / archive_name
    if archive.name != archive_name:
        parser.error(f"Expected {archive_name}, got {archive.name}")
    if args.checksums:
        verify_checksum(archive, args.checksums)

    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if npm is None:
        parser.error("Install Node.js and npm to pack the WASM runtime")
    out = ROOT / "build/release/npm"
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".pack-", dir=out) as temporary:
        stage = Path(temporary) / "package"
        stage.mkdir()
        name = stage_package(archive, stage, version)
        packed = subprocess.check_output([npm, "pack", "--json", "--ignore-scripts"],
                                         cwd=stage, text=True)
        tarball = stage / json.loads(packed)[0]["filename"]

        consumer = Path(temporary) / "consumer"
        consumer.mkdir()
        (consumer / "package.json").write_text('{"private":true}\n', encoding="utf-8")
        subprocess.run([npm, "install", "--offline", "--ignore-scripts", "--no-audit",
                        "--no-fund", str(tarball)], cwd=consumer, check=True)
        entry = consumer / "package-entry.mjs"
        entry.write_text(
            f'import createHybridCPABE from {json.dumps(name)};\n'
            f'import {{ createPqCpAbe, createHybridCpAbe, PqCpAbe, Scheme }} from {json.dumps(name)};\n'
            'import assert from "node:assert/strict";\n'
            'const abe = await createHybridCPABE();\n'
            'assert.equal(abe.ccall("getVersion", "string", [], []), process.argv[2]);\n'
            'assert.equal(createPqCpAbe, createHybridCpAbe);\n'
            'const modern = await createPqCpAbe();\n'
            'const scheme = Scheme.AC17;\n'
            'const keys = modern.setup({ scheme });\n'
            'const secretKey = modern.generateSecretKey({ masterSecretKey: keys.masterSecretKey, attributes: "admin", scheme });\n'
            'const plaintext = Uint8Array.of(0, 1, 255);\n'
            'const ciphertext = modern.encrypt({ publicKey: keys.publicKey, plaintext, policy: "admin", scheme });\n'
            'assert.deepEqual(modern.decrypt({ secretKey, ciphertext }), plaintext);\n'
            'const object = new PqCpAbe(abe, { scheme });\n'
            'assert.deepEqual(object.decrypt({ secretKey, ciphertext }), plaintext);\n',
            encoding="utf-8",
        )
        subprocess.run(["node", str(entry), version], cwd=consumer, check=True)
        command = "pq-cp-abe.cmd" if os.name == "nt" else "pq-cp-abe"
        executable = consumer / "node_modules" / ".bin" / command
        subprocess.run([str(executable), "--test"], cwd=consumer, check=True)
        cli = consumer / "node_modules" / name / "bindings/wasm/cli.mjs"
        subprocess.run(["node", str(ROOT / "tests/wasm/cli.mjs"), str(cli)], cwd=consumer, check=True)
        destination = out / tarball.name
        tarball.replace(destination)
    print(f"Verified npm tarball: {destination}")


if __name__ == "__main__":
    main()
