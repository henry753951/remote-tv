#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
: "${sdk:?Set ANDROID_HOME to your Android SDK directory}"
ndk="${ANDROID_NDK_HOME:-$sdk/ndk/27.0.12077973}"
case "$(uname -s)" in
  Darwin) host=darwin-x86_64 ;;
  Linux) host=linux-x86_64 ;;
  *) echo 'Build on Linux or macOS.' >&2; exit 1 ;;
esac
linker="$ndk/toolchains/llvm/prebuilt/$host/bin/armv7a-linux-androideabi26-clang"
[[ -x "$linker" ]] || { echo 'Install Android NDK 27.0.12077973.' >&2; exit 1; }
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$linker"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=. --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$HOME=/home/build"
cargo build --locked --release --target armv7-linux-androideabi -p atv-android
mkdir -p android-tv/app/src/main/jniLibs/armeabi-v7a
cp "${CARGO_TARGET_DIR:-target}/armv7-linux-androideabi/release/libatv_android.so" android-tv/app/src/main/jniLibs/armeabi-v7a/
cd android-tv
./gradlew :app:assembleRelease :app:lintRelease --max-workers 4
