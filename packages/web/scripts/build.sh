#!/usr/bin/env bash
# Builds the browser core (tether-ffi without media) and the TypeScript package into dist/.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/../.." && pwd)"
cargo build --manifest-path "$root/Cargo.toml" -p tether-ffi --no-default-features \
  --target wasm32-unknown-unknown --release --locked --jobs "${TETHER_JOBS:-2}"
rm -rf "$here/dist"
tsc -p "$here/tsconfig.json"
cp "$root/target/wasm32-unknown-unknown/release/tether_ffi.wasm" "$here/dist/tether.wasm"
echo "built $here/dist ($(wc -c < "$here/dist/tether.wasm" | tr -d ' ') byte core)"
