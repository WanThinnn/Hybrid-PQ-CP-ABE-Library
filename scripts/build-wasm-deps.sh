#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
windows=0
host_suffix=
case "$(uname -s)" in
  Linux) ;;
  Darwin) host_suffix="-macos-$(uname -m)" ;;
  MSYS*|MINGW*|UCRT*|CLANG*) windows=1; host_suffix=-windows ;;
  *) echo 'WASM builds require Linux/WSL, macOS, or Windows MSYS2.' >&2; exit 1 ;;
esac
JOBS="${1:-8}"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid job count' >&2; exit 2; }
unset MAKEFLAGS MFLAGS MAKELEVEL
tools=(emcc em++ emar emranlib emcmake cmake make cargo rustc rustup go python3)
if (( windows )); then tools+=(emcc.exe cygpath ninja); fi
for tool in "${tools[@]}"; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
if command -v sha256sum >/dev/null 2>&1; then
  hash=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash=(shasum -a 256)
else
  echo 'Missing tool: sha256sum or shasum' >&2; exit 1
fi
python3 -c 'import re, sys
version = sys.argv[1]
match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
if not match or tuple(map(int, match.groups())) < (7, 0, 0):
    sys.exit("Use Emscripten SDK 7.0.0 or newer with this Rust WASM build.")' "$(emcc --version)"
rust_toolchain=nightly
DEPS="$ROOT/build/deps/wasm$host_suffix"
set --
if (( windows )); then
  rust_toolchain=nightly-x86_64-pc-windows-msvc
  set -- -G Ninja
  # Rust's default linker on Windows still resolves emcc.bat. SDK 7 uses emcc.exe.
  export CARGO_TARGET_WASM32_UNKNOWN_EMSCRIPTEN_LINKER="$(cygpath -am "$(command -v emcc.exe)")"
fi
rustup component list --installed --toolchain "$rust_toolchain" | grep -q '^rust-src' || {
  echo "Install Rust build support: rustup toolchain install $rust_toolchain --component rust-src" >&2; exit 1;
}
WORK="$DEPS/.work"
mkdir -p "$WORK" "$DEPS/include" "$DEPS/lib"
echo '==> Checking WASM dependency cache (toolchains and sources)'
source_digest="$(python3 scripts/wasm-source-digest.py "$WORK/source-digests.json" \
  vendor/cryptopp vendor/liboqs vendor/circl vendor/librabe-ffi/src \
  vendor/cover_crypt/src bindings/covercrypt/src bindings/tkn20)"
digest="$({
  printf '%s\n' "$source_digest"
  emcc --version && cargo +"$rust_toolchain" --version && rustc +"$rust_toolchain" -vV &&
    (cd bindings/tkn20 && go version) &&
    "${hash[@]}" scripts/{build-wasm-deps.sh,wasm-source-digest.py} vendor/librabe-ffi/rabe.h bindings/covercrypt/include/covercrypt_ffi.h vendor/librabe-ffi/Cargo.{toml,lock} vendor/cover_crypt/Cargo.{toml,lock} bindings/covercrypt/Cargo.{toml,lock}
} | "${hash[@]}" | cut -d' ' -f1)"
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
install_prefix="$WORK/oqs-install"
if (( windows )); then install_prefix="$(cygpath -am "$install_prefix")"; fi
emcmake cmake "$@" -S vendor/liboqs -B "$WORK/liboqs" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$install_prefix" -DCMAKE_INSTALL_LIBDIR=lib \
  -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
  -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
  -DOQS_HAVE_GETENTROPY=ON \
  '-DOQS_MINIMAL_BUILD=KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87'
cmake --build "$WORK/liboqs" --parallel "$JOBS"
cmake --install "$WORK/liboqs"
mkdir -p "$DEPS/lib/liboqs" "$DEPS/include/liboqs"
cp "$WORK/oqs-install/lib/liboqs.a" "$DEPS/lib/liboqs/"
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
  target_dir="$WORK/rust-$dep"
  if (( windows )); then target_dir="$(cygpath -am "$target_dir")"; fi
  CARGO_TARGET_DIR="$target_dir" cargo +"$rust_toolchain" rustc -Zbuild-std=std,panic_abort \
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
  if (( windows )); then goroot="$(cygpath -u "$goroot")"; fi
  install -m 644 "$goroot/lib/wasm/wasm_exec.js" "$DEPS/lib/tkn20/wasm_exec.js"
)
printf '%s\n' "$digest" > "$DEPS/lib/.ready"
echo "WASM dependencies staged in $DEPS"
