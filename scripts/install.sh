#!/usr/bin/env bash
set -euo pipefail
TETHER_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TETHER_PREFIX="${HOME}/.local/share/tether"
if [[ "${1:-}" == "--prefix" && -n "${2:-}" ]]; then TETHER_PREFIX="$2"; shift 2; fi
if [[ $# -ne 0 || "$TETHER_PREFIX" != /* || "$TETHER_PREFIX" == / ]]; then
  echo 'usage: scripts/install.sh [--prefix /absolute/path]' >&2
  exit 2
fi
cd "$TETHER_ROOT"
cargo build --release --locked -p tether --bin tether --jobs 2
TETHER_DIGEST="$(shasum -a 256 target/release/tether | cut -d ' ' -f 1)"
TETHER_NOTICES="$(shasum -a 256 THIRD_PARTY_NOTICES.txt LICENSE | shasum -a 256 | cut -d ' ' -f 1)"
TETHER_RELEASE="$TETHER_PREFIX/releases/0.1.0-${TETHER_DIGEST:0:12}-${TETHER_NOTICES:0:8}"
mkdir -p "$TETHER_PREFIX/bin" "$TETHER_RELEASE"
if [[ -e "$TETHER_PREFIX/bin/tether" && ! -L "$TETHER_PREFIX/bin/tether" ]]; then
  echo 'refusing to replace an unmanaged executable' >&2; exit 1
fi
if [[ -L "$TETHER_PREFIX/bin/tether" ]]; then
  TETHER_PRIOR="$(readlink "$TETHER_PREFIX/bin/tether")"
  case "$TETHER_PRIOR" in "$TETHER_PREFIX"/releases/*/tether) ;; *) echo 'refusing to replace an unmanaged symlink' >&2; exit 1;; esac
fi
if [[ ! -e "$TETHER_RELEASE/tether" ]]; then
  cp target/release/tether "$TETHER_RELEASE/tether"
  chmod 755 "$TETHER_RELEASE/tether"
  cp THIRD_PARTY_NOTICES.txt "$TETHER_RELEASE/THIRD_PARTY_NOTICES.txt"
  cp LICENSE "$TETHER_RELEASE/LICENSE"
fi
[[ "$(shasum -a 256 "$TETHER_RELEASE/tether" | cut -d ' ' -f 1)" == "$TETHER_DIGEST" ]]
cmp -s THIRD_PARTY_NOTICES.txt "$TETHER_RELEASE/THIRD_PARTY_NOTICES.txt"
cmp -s LICENSE "$TETHER_RELEASE/LICENSE"
TETHER_NEXT="$TETHER_PREFIX/bin/.tether-next-$$"
trap 'rm -f "$TETHER_NEXT"' EXIT
ln -s "$TETHER_RELEASE/tether" "$TETHER_NEXT"
mv -f "$TETHER_NEXT" "$TETHER_PREFIX/bin/tether"
"$TETHER_PREFIX/bin/tether" --help >/dev/null
printf 'Installed %s\n' "$TETHER_PREFIX/bin/tether"
