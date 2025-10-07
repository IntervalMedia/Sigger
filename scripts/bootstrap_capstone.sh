#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="$ROOT_DIR/vendor/capstone"
LIB_DIR="$VENDOR_DIR/lib"
INCLUDE_DIR="$VENDOR_DIR/include"
DEFAULT_BUILD_DIR="$VENDOR_DIR/build/host"

: "${CAPSTONE_VERSION:=5.0.1}"
: "${CAPSTONE_URL:=https://github.com/capstone-engine/capstone/archive/refs/tags/$CAPSTONE_VERSION.tar.gz}"
: "${CAPSTONE_BUILD_DIR:=$DEFAULT_BUILD_DIR}"
: "${CAPSTONE_OUTPUT_LIB:=$LIB_DIR/libcapstone.a}"

# shellcheck disable=SC2206
CAPSTONE_CMAKE_ARGS=(${CAPSTONE_CMAKE_ARGS:-})

if [[ ! -d "$INCLUDE_DIR" ]]; then
  echo "error: expected Capstone headers under $INCLUDE_DIR" >&2
  exit 1
fi

mkdir -p "$LIB_DIR" "$CAPSTONE_BUILD_DIR"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

ARCHIVE="$TMPDIR/capstone.tar.gz"

if command -v curl >/dev/null 2>&1; then
  curl -L "$CAPSTONE_URL" -o "$ARCHIVE"
elif command -v wget >/dev/null 2>&1; then
  wget "$CAPSTONE_URL" -O "$ARCHIVE"
else
  echo "error: neither curl nor wget is available to download Capstone" >&2
  exit 1
fi

tar -xzf "$ARCHIVE" -C "$TMPDIR"

SRC_DIR="$(find "$TMPDIR" -maxdepth 1 -mindepth 1 -type d -name 'capstone-*' | head -n1)"
if [[ -z "$SRC_DIR" ]]; then
  echo "error: failed to locate extracted Capstone sources" >&2
  exit 1
fi

cmake -S "$SRC_DIR" -B "$CAPSTONE_BUILD_DIR" -DCAPSTONE_BUILD_STATIC=ON -DCAPSTONE_BUILD_SHARED=OFF \
  -DCMAKE_BUILD_TYPE=Release "${CAPSTONE_CMAKE_ARGS[@]}"
cmake --build "$CAPSTONE_BUILD_DIR" --target capstone --config Release

mkdir -p "$(dirname "$CAPSTONE_OUTPUT_LIB")"
cp "$CAPSTONE_BUILD_DIR"/libcapstone.a "$CAPSTONE_OUTPUT_LIB"

echo "Capstone static library ready at $CAPSTONE_OUTPUT_LIB"
