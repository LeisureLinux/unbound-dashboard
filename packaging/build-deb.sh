#!/bin/bash
# 构建 .deb 包
# 用法: ./build-deb.sh <version> <arch> <binary-path>
# 示例: ./build-deb.sh 0.2.42 amd64 bins/unbound-dashboard

set -e

VERSION="$1"
ARCH="$2"
BINARY="$3"

if [ -z "$VERSION" ] || [ -z "$ARCH" ] || [ -z "$BINARY" ]; then
    echo "用法: $0 <version> <arch> <binary-path>"
    echo "示例: $0 0.2.42 amd64 bins/unbound-dashboard"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
STAGING="/tmp/unbound-dashboard_${VERSION}_${ARCH}"

echo "📦 构建 .deb 包: version=$VERSION arch=$ARCH"

# 清理旧的暂存目录
rm -rf "$STAGING"
mkdir -p "$STAGING/DEBIAN"
mkdir -p "$STAGING/usr/local/bin"
mkdir -p "$STAGING/usr/share/man/man1"
mkdir -p "$STAGING/usr/share/doc/unbound-dashboard"
mkdir -p "$STAGING/etc/systemd/system"

# 复制二进制
cp "$BINARY" "$STAGING/usr/local/bin/unbound-dashboard"
chmod 755 "$STAGING/usr/local/bin/unbound-dashboard"

# 压缩并复制 man 手册
gzip -c -9 "$PROJECT_DIR/man/unbound-dashboard.1" > "$STAGING/usr/share/man/man1/unbound-dashboard.1.gz"
chmod 644 "$STAGING/usr/share/man/man1/unbound-dashboard.1.gz"

# 复制 systemd service
cp "$SCRIPT_DIR/debian/systemd/unbound-dashboard.service" "$STAGING/etc/systemd/system/unbound-dashboard.service"
chmod 644 "$STAGING/etc/systemd/system/unbound-dashboard.service"

# 复制 copyright
cat > "$STAGING/usr/share/doc/unbound-dashboard/copyright" << 'COPYEOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: unbound-dashboard
Upstream-Contact: LeisureLinux <albertxu@freelamp.com>
Source: https://github.com/LeisureLinux/unbound-dashboard

Files: *
Copyright: 2026 LeisureLinux
License: MIT
COPYEOF

# 生成 control 文件（替换变量）
sed -e "s/\${VERSION}/$VERSION/" \
    -e "s/\${ARCH}/$ARCH/" \
    "$SCRIPT_DIR/debian/control" > "$STAGING/DEBIAN/control"

# 复制维护脚本
cp "$SCRIPT_DIR/debian/postinst" "$STAGING/DEBIAN/postinst"
cp "$SCRIPT_DIR/debian/prerm" "$STAGING/DEBIAN/prerm"
cp "$SCRIPT_DIR/debian/postrm" "$STAGING/DEBIAN/postrm"

# 计算 installed-size（KB）
INSTALLED_SIZE=$(du -sk "$STAGING" | awk '{print $1}')
echo "Installed-Size: $INSTALLED_SIZE" >> "$STAGING/DEBIAN/control"

# 构建 .deb
OUTPUT="$PROJECT_DIR/unbound-dashboard_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGING" "$OUTPUT"

echo ""
echo "✅ .deb 包已生成: $OUTPUT"
dpkg-deb --info "$OUTPUT"
echo ""
echo "📋 包内容:"
dpkg-deb --contents "$OUTPUT" | head -20

# 清理
rm -rf "$STAGING"
