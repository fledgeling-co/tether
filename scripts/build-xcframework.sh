#!/bin/bash
set -euo pipefail
TETHER_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TETHER_BUILD_JOBS="${TETHER_BUILD_JOBS:-2}"
# Keep contributor and checkout paths out of distributable panic/debug metadata.
# Cargo's encoded form preserves paths containing spaces and existing encoded flags.
if [[ -z "${CARGO_ENCODED_RUSTFLAGS+x}" ]]; then
  CARGO_ENCODED_RUSTFLAGS="$(python3 -c 'import os; print(chr(31).join(os.environ.get("RUSTFLAGS", "").split()), end="")')"
fi
export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:+${CARGO_ENCODED_RUSTFLAGS}$'\x1f'}--remap-path-prefix=$HOME=/tether/build"$'\x1f'"--remap-path-prefix=$TETHER_ROOT=/tether/source"
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$HOME=/tether/build -ffile-prefix-map=$TETHER_ROOT=/tether/source"
case "$TETHER_BUILD_JOBS" in 1|2) ;; *) echo "TETHER_BUILD_JOBS must be 1 or 2" >&2; exit 1;; esac
TETHER_ARTIFACT="$TETHER_ROOT/packages/TetherKit/Artifacts/TetherFFI.xcframework"
mkdir -p "$(dirname "$TETHER_ARTIFACT")"
TETHER_STAGE="$(mktemp -d "$(dirname "$TETHER_ARTIFACT")/.tether-xcframework.XXXXXX")"
cleanup() {
  if [[ ! -e "$TETHER_ARTIFACT" && -d "$TETHER_STAGE/prior.xcframework" ]]; then
    mv "$TETHER_STAGE/prior.xcframework" "$TETHER_ARTIFACT"
  fi
  rm -rf "$TETHER_STAGE"
}
trap cleanup EXIT
cd "$TETHER_ROOT"
for TETHER_TARGET in aarch64-apple-darwin x86_64-apple-darwin; do
  MACOSX_DEPLOYMENT_TARGET=15.0 cargo build --release --locked -p tether-ffi --target "$TETHER_TARGET" -j "$TETHER_BUILD_JOBS"
done
mkdir -p "$TETHER_STAGE/mac" "$TETHER_STAGE/headers"
lipo -create target/aarch64-apple-darwin/release/libtether_ffi.a target/x86_64-apple-darwin/release/libtether_ffi.a -output "$TETHER_STAGE/mac/libtether_ffi.a"
cp crates/ffi/include/tether.h "$TETHER_STAGE/headers/tether.h"
printf 'module TetherFFI { header "tether.h" export * }\n' > "$TETHER_STAGE/headers/module.modulemap"
TETHER_ARGS=(-create-xcframework -library "$TETHER_STAGE/mac/libtether_ffi.a" -headers "$TETHER_STAGE/headers")
if [[ "${1:-}" != "--mac-only" ]]; then
  for TETHER_TARGET in aarch64-apple-ios aarch64-apple-ios-sim; do
    IPHONEOS_DEPLOYMENT_TARGET=18.0 cargo build --release --locked -p tether-ffi --target "$TETHER_TARGET" -j "$TETHER_BUILD_JOBS"
    TETHER_ARGS+=(-library "$TETHER_ROOT/target/$TETHER_TARGET/release/libtether_ffi.a" -headers "$TETHER_STAGE/headers")
  done
fi
mkdir -p "$(dirname "$TETHER_ARTIFACT")"
# Only replace this script's generated artifact, never source or unrelated framework directories.
xcodebuild "${TETHER_ARGS[@]}" -output "$TETHER_STAGE/TetherFFI.xcframework"
python3 scripts/check-apple-deployment-targets.py --artifact "$TETHER_STAGE/TetherFFI.xcframework"
if [[ -d "$TETHER_ARTIFACT" ]]; then mv "$TETHER_ARTIFACT" "$TETHER_STAGE/prior.xcframework"; fi
mv "$TETHER_STAGE/TetherFFI.xcframework" "$TETHER_ARTIFACT"
