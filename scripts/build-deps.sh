#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PLATFORM="${1:-}"
if [[ -z "$PLATFORM" ]]; then
  case "$(uname -s)" in
    Darwin) PLATFORM="macos" ;;
    *) PLATFORM="linux" ;;
  esac
fi

DEPS_DIR="$ROOT/build/deps/$PLATFORM"
STAGE_DIR="$DEPS_DIR/stage"
INCLUDE_DIR="$DEPS_DIR/include"
STAMP="$DEPS_DIR/.ready"
JOBS="${JOBS:-}"

if [[ -z "$JOBS" ]]; then
  if command -v nproc >/dev/null 2>&1; then
    JOBS="$(nproc)"
  elif command -v sysctl >/dev/null 2>&1; then
    JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
  else
    JOBS=4
  fi
fi

required=(cmake make cargo go g++)
for tool in "${required[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 1; }
done

mkdir -p "$DEPS_DIR" "$STAGE_DIR" "$INCLUDE_DIR/rabe" "$ROOT/lib/static" "$ROOT/lib/dynamic" "$ROOT/bindings/tkn20/include"

if [[ -f "$STAMP"    && -f "$ROOT/lib/static/libcryptopp.a"    && -f "$ROOT/lib/static/liboqs.a"    && -f "$ROOT/lib/static/librabe_ffi.a"    && -f "$ROOT/lib/static/libcpabe_tkn20.a" ]]; then
  echo "Dependencies already built for $PLATFORM. Use 'make deps-clean' to force a rebuild."
  exit 0
fi

echo "==> Crypto++"
make -C vendor/cryptopp -j"$JOBS" static CXXFLAGS="-DNDEBUG -O2 -fPIC"
cp vendor/cryptopp/libcryptopp.a lib/static/libcryptopp.a
make -C vendor/cryptopp clean >/dev/null 2>&1 || true

echo "==> liboqs"
cmake -S vendor/liboqs -B "$DEPS_DIR/liboqs"   -DCMAKE_BUILD_TYPE=Release   -DCMAKE_INSTALL_PREFIX="$STAGE_DIR"   -DBUILD_SHARED_LIBS=OFF   -DOQS_BUILD_ONLY_LIB=ON   -DOQS_USE_OPENSSL=OFF   -DOQS_ALGS_ENABLED=STD
cmake --build "$DEPS_DIR/liboqs" --config Release -j "$JOBS"
cmake --install "$DEPS_DIR/liboqs" --config Release
OQS_LIB="$(find "$STAGE_DIR" -type f -name 'liboqs.a' -print -quit)"
[[ -n "$OQS_LIB" ]] || { echo "liboqs.a not found after build" >&2; exit 1; }
cp "$OQS_LIB" lib/static/liboqs.a
rm -rf "$INCLUDE_DIR/oqs"
cp -R "$STAGE_DIR/include/oqs" "$INCLUDE_DIR/oqs"

echo "==> librabe-ffi"
CARGO_TARGET_DIR="$DEPS_DIR/rabe-target" cargo build --locked --manifest-path vendor/librabe-ffi/Cargo.toml --release
cp "$DEPS_DIR/rabe-target/release/librabe_ffi.a" lib/static/librabe_ffi.a
cp vendor/librabe-ffi/rabe.h "$INCLUDE_DIR/rabe/rabe.h"
if [[ "$PLATFORM" == "macos" ]]; then
  [[ -f "$DEPS_DIR/rabe-target/release/librabe_ffi.dylib" ]] && cp "$DEPS_DIR/rabe-target/release/librabe_ffi.dylib" lib/dynamic/librabe_ffi.dylib
else
  [[ -f "$DEPS_DIR/rabe-target/release/librabe_ffi.so" ]] && cp "$DEPS_DIR/rabe-target/release/librabe_ffi.so" lib/dynamic/librabe_ffi.so
fi

echo "==> CIRCL/TKN20 C bridge"
TKN_DIR="$DEPS_DIR/tkn20"
mkdir -p "$TKN_DIR"
(
  cd bindings/tkn20
  CGO_ENABLED=1 go build -buildmode=c-archive -o "$TKN_DIR/libcpabe_tkn20.a" .
)
cp "$TKN_DIR/libcpabe_tkn20.a" lib/static/libcpabe_tkn20.a
cp "$TKN_DIR/libcpabe_tkn20.h" bindings/tkn20/include/cpabe_tkn20.h
if [[ "$PLATFORM" == "macos" ]]; then
  (
    cd bindings/tkn20
    CGO_ENABLED=1 go build -buildmode=c-shared -o "$TKN_DIR/libcpabe_tkn20.dylib" .
  )
  cp "$TKN_DIR/libcpabe_tkn20.dylib" lib/dynamic/libcpabe_tkn20.dylib
else
  (
    cd bindings/tkn20
    CGO_ENABLED=1 go build -buildmode=c-shared -o "$TKN_DIR/libcpabe_tkn20.so" .
  )
  cp "$TKN_DIR/libcpabe_tkn20.so" lib/dynamic/libcpabe_tkn20.so
fi

printf '%s\n' "platform=$PLATFORM" > "$STAMP"
printf '%s\n' "cryptopp=5873a73a231c95771f5bbf3466a484952fb22780" >> "$STAMP"
printf '%s\n' "liboqs=e1f480f382d9443c4412133b55948374c77a5c21" >> "$STAMP"
printf '%s\n' "librabe-ffi=ff828d13a635042c9569cfb29117f299b553f946" >> "$STAMP"
printf '%s\n' "circl=901199c7d4fcefc8c43e8ad46397439ccd3a0ed0" >> "$STAMP"

echo "Dependencies built successfully for $PLATFORM."
