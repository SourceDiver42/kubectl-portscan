#!/usr/bin/env bash
# Builds release archives for BOTH plugin names from one compiled binary.
# Output: dist/kubectl-{portscan,nmap}_<os>_<arch>.tar.gz plus checksums.
# Usage: scripts/dist.sh
set -euo pipefail

cd "$(dirname "$0")/.."
PLATFORMS=("linux/amd64" "linux/arm64" "darwin/arm64")
NAMES=("portscan" "nmap")

rm -rf dist
mkdir -p dist/build dist/stage

for p in "${PLATFORMS[@]}"; do
  os="${p%/*}"; arch="${p#*/}"
  out="dist/build/${os}-${arch}"
  mkdir -p "$out"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o "$out/kubectl-portscan" .

  for n in "${NAMES[@]}"; do
    stage="dist/stage/${n}-${os}-${arch}"
    mkdir -p "$stage"
    cp "$out/kubectl-portscan" "$stage/kubectl-${n}"
    [ -f LICENSE ] && cp LICENSE "$stage/"
    tar -C "$stage" -czf "dist/kubectl-${n}_${os}_${arch}.tar.gz" .
  done
done

rm -rf dist/build dist/stage
( cd dist && { sha256sum *.tar.gz 2>/dev/null || shasum -a 256 *.tar.gz; } | tee checksums.txt )
echo "Run scripts/render-krew.sh <version> to write these into plugins/*.yaml"
