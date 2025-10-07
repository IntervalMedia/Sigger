#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/ios"
mkdir -p "$BUILD_DIR"

: "${IOS_MIN_VERSION:=12.0}"
: "${ARCH:=arm64}"

if command -v xcrun >/dev/null 2>&1; then
  SDK_PATH="${SDK_PATH:-$(xcrun --sdk iphoneos --show-sdk-path)}"
  CC_BIN="${CC:-$(xcrun --sdk iphoneos --find clang)}"
else
  SDK_PATH="${SDK_PATH:-}"
  CC_BIN="${CC:-clang}"
  if [[ -z "$SDK_PATH" ]]; then
    echo "warning: xcrun not found and SDK_PATH not provided; attempting to use default toolchain" >&2
  fi
fi

IOS_LIB_DIR="$ROOT_DIR/vendor/capstone/lib/ios-$ARCH"
IOS_LIB="$IOS_LIB_DIR/libcapstone.a"

if [[ ! -f "$IOS_LIB" ]]; then
  echo "Capstone iOS static library not found; bootstrapping one now..." >&2
  CAPSTONE_ARGS=("-DCMAKE_OSX_ARCHITECTURES=$ARCH" "-DCMAKE_OSX_DEPLOYMENT_TARGET=$IOS_MIN_VERSION")
  if [[ -n "$SDK_PATH" ]]; then
    CAPSTONE_ARGS+=("-DCMAKE_OSX_SYSROOT=$SDK_PATH")
  fi
  CAPSTONE_CMAKE_ARGS="${CAPSTONE_ARGS[*]}" \
    CAPSTONE_BUILD_DIR="$ROOT_DIR/vendor/capstone/build/ios-$ARCH" \
    CAPSTONE_OUTPUT_LIB="$IOS_LIB" \
    "$ROOT_DIR/scripts/bootstrap_capstone.sh"
fi

CXXFLAGS=(
  -std=c++17
  -fvisibility=hidden
  -fvisibility-inlines-hidden
  -Wl,-dead_strip
  -Os
  -arch "$ARCH"
  -miphoneos-version-min="$IOS_MIN_VERSION"
)

if [[ -n "$SDK_PATH" ]]; then
  CXXFLAGS+=( -isysroot "$SDK_PATH" )
fi

INCLUDE_FLAGS=(
  -I"$ROOT_DIR"
  -I"$ROOT_DIR/vendor/capstone/include"
)

LIB_FLAGS=(
  -L"$IOS_LIB_DIR"
  -lcapstone
)

"$CC_BIN" "${CXXFLAGS[@]}" "${INCLUDE_FLAGS[@]}" "$ROOT_DIR/sigger.cpp" \
  "${LIB_FLAGS[@]}" -pthread -o "$BUILD_DIR/sigger"

cat <<MSG
Built iOS executable:
  $BUILD_DIR/sigger
MSG
