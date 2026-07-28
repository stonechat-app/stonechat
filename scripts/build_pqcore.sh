#!/usr/bin/env bash
# Build the pqcore Rust crate for every platform the app ships on.
#
#   ./scripts/build_pqcore.sh host      # dylib/so for flutter test on this machine
#   ./scripts/build_pqcore.sh android   # .so per ABI into app/android jniLibs
#   ./scripts/build_pqcore.sh ios       # universal staticlib + module for Xcode
#   ./scripts/build_pqcore.sh all
#
# Prereqs: rustup; for android `cargo install cargo-ndk` plus NDK targets
# (rustup target add aarch64-linux-android armv7-linux-androideabi
#  x86_64-linux-android); for ios (rustup target add aarch64-apple-ios
#  aarch64-apple-ios-sim x86_64-apple-ios).
set -euo pipefail
cd "$(dirname "$0")/../pqcore"

host() {
  cargo build --release
  echo "host library: $(ls ../pqcore/target/release/libpqcore.* 2>/dev/null | tr '\n' ' ')"
  echo "for flutter test: export STONECHAT_PQCORE_LIB=\$PWD/target/release/libpqcore.dylib"
}

android() {
  cargo ndk \
    -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o ../app/android/app/src/main/jniLibs \
    build --release
}

ios() {
  for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    cargo build --release --target "$t"
  done
  mkdir -p target/ios-sim-universal
  lipo -create \
    target/aarch64-apple-ios-sim/release/libpqcore.a \
    target/x86_64-apple-ios/release/libpqcore.a \
    -output target/ios-sim-universal/libpqcore.a
  rm -rf target/PqCore.xcframework
  xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libpqcore.a \
    -library target/ios-sim-universal/libpqcore.a \
    -output target/PqCore.xcframework
  echo "add target/PqCore.xcframework to the Runner target — the symbols land"
  echo "in the app binary, which is what DynamicLibrary.process() resolves"
  echo "against. Nothing references them at link time, so keep the linker from"
  echo "stripping: OTHER_LDFLAGS += -force_load path/to/libpqcore.a"
}

case "${1:-all}" in
  host) host ;;
  android) android ;;
  ios) ios ;;
  all) host; android; ios ;;
  *) echo "usage: $0 [host|android|ios|all]" >&2; exit 1 ;;
esac
