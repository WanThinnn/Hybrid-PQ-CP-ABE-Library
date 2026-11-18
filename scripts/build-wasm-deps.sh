#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
[[ "$(uname -s)" == Linux ]] || { echo 'WASM builds require Linux (or WSL).' >&2; exit 1; }
JOBS="${1:-8}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid job count' >&2; exit 2; }
unset MAKEFLAGS MFLAGS MAKELEVEL
for tool in emcc em++ emar emcmake cmake make cargo rustup go python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
python3 -c 'import re, subprocess, sys
version = subprocess.check_output(["emcc", "--version"], text=True)
match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
if not match or tuple(map(int, match.groups())) < (7, 0, 0):
    sys.exit("Use Emscripten SDK 7.0.0 or newer with this Rust WASM build.")'
rustup component list --installed --toolchain nightly | grep -q '^rust-src' || {
  echo 'Install Rust build support: rustup toolchain install nightly --component rust-src' >&2; exit 1;
}
DEPS="$ROOT/build/deps/wasm"
WORK="$DEPS/.work"
mkdir -p "$WORK" "$DEPS/include" "$DEPS/lib"
# Include source contents and compiler versions: make wasm-deps also notices
# local vendor edits, not just upstream version labels.
digest="$({
  emcc --version; cargo +nightly --version; rustc +nightly -vV
  (cd bindings/tkn20 && go version)
  find vendor/cryptopp vendor/liboqs vendor/circl vendor/librabe-ffi/src vendor/cover_crypt/src bindings/covercrypt/src bindings/tkn20 \
    -type f ! -path '*/.git/*' ! -path '*/target/*' -print0 | sort -z | xargs -0 sha256sum
  sha256sum scripts/build-wasm-deps.sh vendor/librabe-ffi/rabe.h bindings/covercrypt/include/covercrypt_ffi.h vendor/librabe-ffi/Cargo.{toml,lock} vendor/cover_crypt/Cargo.{toml,lock} bindings/covercrypt/Cargo.{toml,lock}
} | sha256sum | cut -d' ' -f1)"
outputs=(lib/cryptopp/libcryptopp.a lib/liboqs/liboqs.a lib/rabe/librabe_ffi.a lib/covercrypt/libcovercrypt_ffi.a lib/tkn20/tkn20.wasm lib/tkn20/wasm_exec.js include/cryptopp/aes.h include/liboqs/oqs/oqs.h include/rabe/rabe.h include/covercrypt/covercrypt_ffi.h)
cached=true
for output in "${outputs[@]}"; do [[ -f "$DEPS/$output" ]] || cached=false; done
if $cached && [[ -f "$DEPS/lib/.ready" ]] && [[ "$(cat "$DEPS/lib/.ready")" == "$digest" ]]; then
  echo 'WASM dependencies: cached'; exit 0
fi
rm -f "$DEPS/lib/.ready"

echo '==> Crypto++ (portable WASM, no native assembly)'
mkdir -p "$WORK/cryptopp" "$DEPS/include/cryptopp" "$DEPS/lib/cryptopp"
cp -a vendor/cryptopp/. "$WORK/cryptopp/"
make -C "$WORK/cryptopp" clean >/dev/null 2>&1 || true
make -C "$WORK/cryptopp" -j"$JOBS" static CXX=em++ AR=emar RANLIB=emranlib \
  CXXFLAGS='-O2 -DNDEBUG -DCRYPTOPP_DISABLE_ASM -fexceptions'
cp "$WORK/cryptopp/libcryptopp.a" "$DEPS/lib/cryptopp/"
cp "$WORK/cryptopp/"*.h "$DEPS/include/cryptopp/"

echo '==> liboqs (portable ML-KEM + ML-DSA)'
# CMake otherwise retains the previous SDK's absolute compiler paths.
rm -rf "$WORK/liboqs" "$WORK/oqs-install"
emcmake cmake -S vendor/liboqs -B "$WORK/liboqs" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$WORK/oqs-install" \
  -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
  -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
  -DOQS_HAVE_GETENTROPY=ON \
  '-DOQS_MINIMAL_BUILD=KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87'
cmake --build "$WORK/liboqs" --parallel "$JOBS"
cmake --install "$WORK/liboqs"
mkdir -p "$DEPS/lib/liboqs" "$DEPS/include/liboqs"
cp "$(find "$WORK/oqs-install" -name liboqs.a -print -quit)" "$DEPS/lib/liboqs/"
cp -R "$WORK/oqs-install/include/oqs" "$DEPS/include/liboqs/"

# Rebuild std with the installed Emscripten ABI. Both Rust archives use abort
# panics and no LTO; the C++ layer retains its own exception handling.
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_PANIC=abort
export RUSTFLAGS='-C panic=abort'
for dep in rabe covercrypt; do
  if [[ "$dep" == rabe ]]; then
    manifest=vendor/librabe-ffi/Cargo.toml; name=rabe_ffi
    header=vendor/librabe-ffi/rabe.h
  else
    manifest=bindings/covercrypt/Cargo.toml; name=covercrypt_ffi
    header=bindings/covercrypt/include/covercrypt_ffi.h
  fi
  echo "==> $dep (Rust/Emscripten static archive)"
  CARGO_TARGET_DIR="$WORK/rust-$dep" cargo +nightly rustc -Zbuild-std=std,panic_abort \
    --locked --release --jobs "$JOBS" --target wasm32-unknown-emscripten \
    --manifest-path "$manifest" --lib --crate-type staticlib
  mkdir -p "$DEPS/lib/$dep" "$DEPS/include/$dep"
  cp "$WORK/rust-$dep/wasm32-unknown-emscripten/release/lib$name.a" "$DEPS/lib/$dep/"
  cp "$header" "$DEPS/include/$dep/"
done

echo '==> TKN20 (Go js/wasm runtime)'
mkdir -p "$DEPS/lib/tkn20"
(
  cd bindings/tkn20
  GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -mod=readonly -p "$JOBS" -o "$DEPS/lib/tkn20/tkn20.wasm" .
  goroot="$(go env GOROOT)"
  install -m 644 "$goroot/lib/wasm/wasm_exec.js" "$DEPS/lib/tkn20/wasm_exec.js"
)
printf '%s\n' "$digest" > "$DEPS/lib/.ready"
echo "WASM dependencies staged in $DEPS"
