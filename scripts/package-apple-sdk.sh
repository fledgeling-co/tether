#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
[ -d packages/TetherKit/Artifacts/TetherFFI.xcframework ] || { echo 'Build the XCFramework first.' >&2; exit 1; }
[ -x packages/TetherKit/Artifacts/Helpers/tether ] || { echo 'Run scripts/build-apple-helper.sh first.' >&2; exit 1; }
version="${1:-0.1.0-frameworks.1}"
case "$version" in *[!a-zA-Z0-9._-]*|'') echo 'Invalid package version.' >&2; exit 1;; esac
stage="$(mktemp -d /tmp/tether-apple-package.XXXXXX)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/TetherKit/Artifacts" "$stage/TetherKit/docs" "$root/.status/releases"
cp packages/TetherKit/Package.swift packages/TetherKit/README.md "$stage/TetherKit/"
cp -R packages/TetherKit/Sources packages/TetherKit/Tests "$stage/TetherKit/"
cp -R packages/TetherKit/Artifacts/TetherFFI.xcframework "$stage/TetherKit/Artifacts/"
cp -R packages/TetherKit/Artifacts/Helpers "$stage/TetherKit/Artifacts/"
cp LICENSE THIRD_PARTY_NOTICES.txt "$stage/TetherKit/"
cp docs/FRAMEWORKS.md docs/protocol-v1.json "$stage/TetherKit/docs/"
output="$root/.status/releases/TetherKit-$version-Apple.zip"
[ ! -e "$output" ] || { echo 'Package exists; choose a new immutable version.' >&2; exit 1; }
(cd "$stage" && /usr/bin/ditto -c -k --keepParent TetherKit "$output")
/usr/bin/shasum -a 256 "$output"
