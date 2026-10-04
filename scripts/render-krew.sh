#!/usr/bin/env bash
# Regenerates krew/portscan.yaml and krew/nmap.yaml for a given version,
# pulling each sha256 from dist/checksums.txt (produced by scripts/dist.sh).
# This is the single source of truth for the manifests; don't hand-edit them.
#
# Usage: scripts/render-krew.sh [VERSION]
#   VERSION defaults to the exact tag at HEAD, else v0.0.0 (for dry runs).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --exact-match 2>/dev/null || echo v0.0.0)}"
DIST="${DIST:-dist}"
REPO="github.com/SourceDiver42/kubectl-portscan"

if [ ! -f "$DIST/checksums.txt" ]; then
  echo "error: $DIST/checksums.txt not found; run scripts/dist.sh first" >&2
  exit 1
fi

sha() { # <name> <os_arch> -> sha256, errors if missing
  local file="kubectl-$1_$2.tar.gz" s
  s="$(awk -v f="$file" '$2==f {print $1}' "$DIST/checksums.txt")"
  if [ -z "$s" ]; then echo "error: no checksum for $file" >&2; exit 1; fi
  printf '%s' "$s"
}

render() { # <name> <other-name>
  local name="$1" other="$2"
  cat > "krew/${name}.yaml" <<EOF
apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: ${name}
spec:
  version: ${VERSION}
  homepage: https://${REPO}
  shortDescription: Run nmap from inside the cluster
  description: |
    Runs nmap in an ephemeral pod, optionally pinned to a node and/or on the
    host network, so you can test firewalls and exposed ports on nodes without
    shell access (e.g. Talos). Each run creates a throwaway namespace labelled
    pod-security.kubernetes.io/enforce=privileged and deletes it afterwards.
  caveats: |
    Creates a privileged namespace and a pod with NET_RAW/NET_ADMIN (or none
    with --scan-type connect). Requires RBAC to create namespaces and pods.
    Also available as \`kubectl ${other}\` (separate plugin entry, same binary).
  platforms:
  - selector:
      matchLabels: {os: linux, arch: amd64}
    uri: https://${REPO}/releases/download/${VERSION}/kubectl-${name}_linux_amd64.tar.gz
    sha256: $(sha "$name" linux_amd64)
    bin: kubectl-${name}
  - selector:
      matchLabels: {os: linux, arch: arm64}
    uri: https://${REPO}/releases/download/${VERSION}/kubectl-${name}_linux_arm64.tar.gz
    sha256: $(sha "$name" linux_arm64)
    bin: kubectl-${name}
  - selector:
      matchLabels: {os: darwin, arch: arm64}
    uri: https://${REPO}/releases/download/${VERSION}/kubectl-${name}_darwin_arm64.tar.gz
    sha256: $(sha "$name" darwin_arm64)
    bin: kubectl-${name}
EOF
}

render portscan nmap
render nmap portscan
echo "Rendered krew/portscan.yaml and krew/nmap.yaml for ${VERSION}"
