#!/bin/bash
set -euo pipefail
TETHER_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TETHER_BUILD_JOBS="${TETHER_BUILD_JOBS:-2}"
case "$TETHER_BUILD_JOBS" in 1|2) ;; *) echo "TETHER_BUILD_JOBS must be 1 or 2" >&2; exit 1;; esac
cd "$TETHER_ROOT"
TETHER_DEST="$TETHER_ROOT/packages/TetherKit/Artifacts/Helpers"
mkdir -p "$TETHER_DEST"
TETHER_STAGE="$(mktemp -d "$TETHER_DEST/.helper.XXXXXX")"
trap 'rm -rf "$TETHER_STAGE"' EXIT
for TETHER_TARGET in aarch64-apple-darwin x86_64-apple-darwin; do
  MACOSX_DEPLOYMENT_TARGET=15.0 cargo build --release --locked -p tether --target "$TETHER_TARGET" -j "$TETHER_BUILD_JOBS"
done
lipo -create target/aarch64-apple-darwin/release/tether target/x86_64-apple-darwin/release/tether -output "$TETHER_STAGE/tether"
# SDK helpers are development components; the embedding app signs and notarizes its bundle.
codesign --force --sign - "$TETHER_STAGE/tether"
python3 - "$TETHER_STAGE/tether" <<'PY_HELPER'
import re, subprocess, sys
binary = sys.argv[1]
arches = subprocess.check_output(['lipo', '-archs', binary], text=True).split()
if set(arches) != {'arm64', 'x86_64'}:
    raise SystemExit('Expected universal Mac helper')
for arch in arches:
    commands = subprocess.check_output(['otool', '-arch', arch, '-l', binary], text=True)
    minimums = re.findall(r'\bminos ([0-9.]+)', commands)
    platforms = re.findall(r'\bplatform (\S+)', commands)
    if not minimums or any(tuple(map(int, v.split('.'))) > (15, 0) for v in minimums):
        raise SystemExit('Mac helper exceeds macOS15 deployment floor')
    if not platforms or any(p not in ('1', 'MACOS') for p in platforms):
        raise SystemExit('Mac helper has incorrect platform metadata')
    print(arch + ': macOS ' + ','.join(minimums))
PY_HELPER
chmod 755 "$TETHER_STAGE/tether"
# Rename replaces one generated executable atomically, retaining the previous build on failure.
mv -f "$TETHER_STAGE/tether" "$TETHER_DEST/tether"
shasum -a 256 "$TETHER_DEST/tether"
