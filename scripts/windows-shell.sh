#!/bin/sh
# Run a Windows Make recipe without MSYS/Cygwin rewriting its quotes or flags.
set -eu
recipe=$(mktemp "${TMPDIR:-/tmp}/hybrid-cp-abe.XXXXXXXX.cmd")
trap 'rm -f "$recipe"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf '@echo off\r\n%s\r\n' "$1" > "$recipe"
native_recipe=$(cygpath -w "$recipe")
MSYS2_ARG_CONV_EXCL='*' cmd.exe /d /c "$native_recipe"
