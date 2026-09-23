#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> 检查并整理 Go 依赖"
go mod tidy

echo "==> 正在编译 Go 为 WebAssembly (vpn2qr.wasm)..."
mkdir -p ../public
GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o ../public/vpn2qr.wasm .

echo "==> 复制 Go 官方 wasm_exec.js 桥接脚本"
GOROOT="$(go env GOROOT)"
if [ -f "${GOROOT}/misc/wasm/wasm_exec.js" ]; then
  cp "${GOROOT}/misc/wasm/wasm_exec.js" ../public/wasm_exec.js
elif [ -f "${GOROOT}/lib/wasm/wasm_exec.js" ]; then
  cp "${GOROOT}/lib/wasm/wasm_exec.js" ../public/wasm_exec.js
fi

echo "==> 编译完成！产物已输出至 public/ 目录"
ls -lh ../public/vpn2qr.wasm ../public/wasm_exec.js || true
