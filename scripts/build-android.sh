#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
android_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
android_ndk="${ANDROID_NDK_HOME:-$android_sdk/ndk/27.1.12297006}"
case "$(uname -s)" in Darwin) toolchain="$android_ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin";; Linux) toolchain="$android_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin";; *) echo 'Use the Android NDK cross-build on macOS or Linux.' >&2; exit 64;; esac
[ -x "$toolchain/aarch64-linux-android26-clang" ] || { echo 'Install Android NDK 27.1.12297006 and set ANDROID_NDK_HOME.' >&2; exit 1; }
android_ndk_real="$(cd "$android_ndk" && pwd -P)"
export CARGO_BUILD_JOBS=1
# Remove workstation source paths from Rust panic sites and native C file metadata.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/tether/build --remap-path-prefix=$root=/tether/source"
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$HOME=/tether/build -ffile-prefix-map=$root=/tether/source -ffile-prefix-map=$android_ndk_real=/tether/ndk"
for triple in aarch64-linux-android x86_64-linux-android; do
  rustup target list --installed | grep -Fxq "$triple" || { echo "Run: rustup target add $triple" >&2; exit 1; }
  upper="$(echo "$triple" | tr '[:lower:]-' '[:upper:]_')"
  underscored="${triple//-/_}"
  env "CARGO_TARGET_${upper}_LINKER=$toolchain/${triple}26-clang" "CC_${underscored}=$toolchain/${triple}26-clang" "AR_${underscored}=$toolchain/llvm-ar" \
    cargo build --manifest-path "$root/Cargo.toml" --locked --release --jobs 1 --target "$triple" -p tether-ffi
  [ -s "$root/target/$triple/release/libtether_ffi.a" ] || exit 1
  printf '%s\n' "Built Android core: $triple"
done
