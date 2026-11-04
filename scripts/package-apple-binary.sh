#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
artifact="$root/packages/TetherKit/Artifacts/TetherFFI.xcframework"
output="${1:-$root/.status/releases/TetherFFI.xcframework.zip}"
[ -d "$artifact" ] || { echo 'Build the Apple XCFramework first.' >&2; exit 1; }
[ ! -e "$output" ] || { echo 'Output exists; preserve the immutable artifact.' >&2; exit 1; }
find "$artifact" -name '*.a' -print0 | xargs -0 python3 "$root/scripts/check-binary-paths.py"
stage="$(mktemp -d /tmp/tether-apple-binary.XXXXXX)"
trap 'rm -rf "$stage"' EXIT
cp -R "$artifact" "$stage/TetherFFI.xcframework"
cp "$root/LICENSE" "$root/THIRD_PARTY_NOTICES.txt" "$stage/TetherFFI.xcframework/"
python3 "$root/scripts/check-apple-deployment-targets.py" --artifact "$stage/TetherFFI.xcframework"
mkdir -p "$(dirname "$output")"
/usr/bin/ditto -c -k --keepParent "$stage/TetherFFI.xcframework" "$output"
swift package compute-checksum "$output"
