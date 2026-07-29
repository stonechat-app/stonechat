#!/usr/bin/env bash
# Build stonechat-core (repo /core) for every platform the app ships on.
# One artifact serves both ABIs: the session engine AND pqcore's KEM
# symbols ride in the same library (core depends on pqcore), so this
# supersedes the old build_pqcore.sh entirely.
#
#   ./scripts/build_core.sh host      # dylib/so for flutter test + python tooling
#   ./scripts/build_core.sh android   # .so per ABI into app/android jniLibs
#   ./scripts/build_core.sh ios       # device staticlib into app/ios/Core/
#   ./scripts/build_core.sh all
#
# Prereqs: rustup; for android `cargo install cargo-ndk` plus NDK targets
# (rustup target add aarch64-linux-android armv7-linux-androideabi
#  x86_64-linux-android); for ios (rustup target add aarch64-apple-ios
#  aarch64-apple-ios-sim x86_64-apple-ios).
set -euo pipefail
cd "$(dirname "$0")/../core"

host() {
  cargo build --release
  echo "host library: $(ls target/release/libstonechat_core.* 2>/dev/null | tr '\n' ' ')"
  echo "for flutter test: export STONECHAT_CORE_LIB=\$PWD/target/release/libstonechat_core.dylib"
}

android() {
  cargo ndk \
    -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o ../app/android/app/src/main/jniLibs \
    build --release
}

ios() {
  # The Runner links the device staticlib directly with -force_load (see
  # OTHER_LDFLAGS in project.pbxproj) so the symbols survive into the app
  # binary, which is what DynamicLibrary.process() resolves against.
  rustup target add aarch64-apple-ios >/dev/null 2>&1 || true
  cargo build --release --target aarch64-apple-ios
  mkdir -p ../app/ios/Core
  cp target/aarch64-apple-ios/release/libstonechat_core.a ../app/ios/Core/
  echo "installed: app/ios/Core/libstonechat_core.a"

  # Simulator slice, built on demand for `flutter run` on a simulator:
  #   cargo build --release --target aarch64-apple-ios-sim
  # and point OTHER_LDFLAGS at it, or lipo/xcframework as needed.
}

case "${1:-all}" in
  host) host ;;
  android) android ;;
  ios) ios ;;
  all) host; ios ;;
  *) echo "usage: $0 [host|android|ios|all]" >&2; exit 1 ;;
esac
