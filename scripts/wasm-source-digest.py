#!/usr/bin/env python3
"""Fingerprint WASM sources, reusing hashes for unchanged files."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


def source_files(directory):
    with os.scandir(directory) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(info.st_mode):
                yield entry.path, info
            elif stat.S_ISDIR(info.st_mode) and entry.name not in {".git", "target"}:
                yield from source_files(entry.path)


def main():
    cache_path = Path(sys.argv[1])
    # Native Windows Python exposes creation time as st_ctime, so it cannot
    # detect a same-size edit whose mtime was restored.
    reuse_hashes = os.name != "nt"
    try:
        previous = json.loads(cache_path.read_text(encoding="utf-8")) if reuse_hashes else {}
    except (FileNotFoundError, ValueError):
        previous = {}
    if not isinstance(previous, dict):
        previous = {}

    current = {}
    for directory in sys.argv[2:]:
        for path, info in source_files(directory):
            signature = [info.st_dev, info.st_ino, info.st_size,
                         info.st_mtime_ns, info.st_ctime_ns]
            cached = previous.get(path)
            if isinstance(cached, list) and len(cached) == 2 and cached[0] == signature:
                current[path] = cached
                continue

            digest = hashlib.sha256()
            with open(path, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            current[path] = [signature, digest.hexdigest()]

    if reuse_hashes and current != previous:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                         dir=cache_path.parent, delete=False) as temp:
            temporary_path = Path(temp.name)
            try:
                json.dump(current, temp)
                temp.close()
                temporary_path.replace(cache_path)
            finally:
                temporary_path.unlink(missing_ok=True)

    contents = [(path, current[path][1]) for path in sorted(current)]
    print(hashlib.sha256(json.dumps(contents).encode("ascii")).hexdigest())


if __name__ == "__main__":
    main()
