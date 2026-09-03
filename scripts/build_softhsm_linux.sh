#!/usr/bin/env bash
# Build SoftHSM2 2.7.0 from the submodule on Linux with OpenSSL backend.
# Output: installed under <repo_root>/softhsm2-install/
#
# Prerequisites (Debian/Ubuntu):
#   sudo apt-get install -y build-essential autoconf automake libtool \
#                           libssl-dev pkg-config
# Prerequisites (Fedora/RHEL):
#   sudo dnf install -y gcc-c++ autoconf automake libtool openssl-devel

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$REPO_ROOT/softhsm2"
INSTALL_DIR="$REPO_ROOT/softhsm2-install"
BUILD_DIR="$REPO_ROOT/softhsm2-build-linux"
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "=== SoftHSM2 2.7.0 — Linux build (OpenSSL backend) ==="
echo "Source  : $SRC_DIR"
echo "Install : $INSTALL_DIR"
echo "Jobs    : $JOBS"
echo ""

# Verify submodule has been initialised
if [ ! -f "$SRC_DIR/configure.ac" ]; then
    echo "ERROR: softhsm2 submodule not found. Run first:"
    echo "  git submodule update --init --recursive"
    exit 1
fi

# ── Option A: CMake build (preferred for 2.7.0) ──────────────────────────────
if command -v cmake &>/dev/null && cmake --version | grep -q "cmake version [3-9]"; then
    echo ">>> Using CMake build"
    mkdir -p "$BUILD_DIR"
    cmake -S "$SRC_DIR" -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
        -DWITH_CRYPTO_BACKEND=openssl \
        -DENABLE_ECC=ON \
        -DENABLE_EDDSA=ON \
        -DENABLE_GOST=OFF \
        -DBUILD_TESTS=OFF \
        -DWITH_OBJECTSTORE_BACKEND_DB=OFF \
        -DENABLE_P11_KIT=OFF
    cmake --build "$BUILD_DIR" --parallel "$JOBS"
    cmake --install "$BUILD_DIR"
else
    # ── Option B: autotools fallback ─────────────────────────────────────────
    echo ">>> Using autotools build"
    cd "$SRC_DIR"
    if [ ! -f configure ]; then
        autoreconf -fi
    fi
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    "$SRC_DIR/configure" \
        --prefix="$INSTALL_DIR" \
        --with-crypto-backend=openssl \
        --enable-ecc \
        --disable-gost \
        --disable-p11-kit
    make -j"$JOBS"
    make install
fi

echo ""
echo "=== Build complete ==="
echo ""
echo "Library : $INSTALL_DIR/lib/softhsm/libsofthsm2.so"
echo ""
echo "To initialise a token:"
echo "  export SOFTHSM2_CONF=$INSTALL_DIR/etc/softhsm2.conf"
echo "  mkdir -p $INSTALL_DIR/var/lib/softhsm/tokens"
echo "  $INSTALL_DIR/bin/softhsm2-util --init-token --slot 0 \\"
echo "      --label MyToken --so-pin 0000 --pin 1234"
echo ""
echo "To run KSP unit tests with this library:"
echo "  export SOFTHSM2_CONF=$INSTALL_DIR/etc/softhsm2.conf"
echo "  cd softhsm_ksp/tests/unit && make && ./test_p11rv_mapping && ..."
