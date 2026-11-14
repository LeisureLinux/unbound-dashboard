#!/bin/bash
# Build amd64 + arm64 binaries. Version comes from the git tag; no source
# file is modified (the old script sed-ed a const in cmd/main.go).
#
# Usage: ./build.sh [version]

set -euo pipefail

cd "$(dirname "$0")"
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
echo "版本: $VERSION"

mkdir -p bins

build() {
    local goarch="$1" cc="$2" out="$3"
    echo "正在编译 $goarch → $out ..."
    GOOS=linux GOARCH="$goarch" CGO_ENABLED=1 CC="$cc" \
        go build -ldflags="-s -w -X main.Version=$VERSION" -o "$out" ./cmd/
    file "$out"
    sha256sum "$out"
}

build amd64 gcc bins/unbound-dashboard
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    build arm64 aarch64-linux-gnu-gcc bins/unbound-dashboard-arm64
else
    echo "⚠️  跳过 arm64：未安装 aarch64-linux-gnu-gcc"
    echo "   sudo apt install gcc-aarch64-linux-gnu"
fi

echo "✅ 编译完成"
