"""Export every public C function, plus allocator and CLI entry point."""
import json
import re
import sys
from pathlib import Path

header = Path(sys.argv[1]).read_text(encoding="utf-8")
names = re.findall(r"^\s*LIB_API[ \t]+[^;{}]*?\b(\w+)\s*\(", header, re.MULTILINE)
Path(sys.argv[2]).write_text(json.dumps(["_malloc", "_free", "_main"] + ["_" + n for n in names]) + "\n")
