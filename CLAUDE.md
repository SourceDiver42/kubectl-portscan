# kubectl-portscan

Run nmap from *inside* the cluster, for nodes where you can't (or don't want to) get a shell, such as Talos.

Each run:

1. creates a throwaway namespace labelled `pod-security.kubernetes.io/{enforce,audit,warn}=privileged`
2. starts a single `scanner` pod (optionally pinned with `--from-node`, optionally `--host-network`)
3. waits, reads the logs, parses nmap's XML
4. deletes the namespace (also on Ctrl-C)

## Build

```sh
# replace the module path in go.mod first
go mod tidy
go vet ./...
go build -o kubectl-portscan .
mv kubectl-portscan ~/.local/bin/    # anything on $PATH named kubectl-*
kubectl portscan --help
```

## Two names: `portscan` and `nmap`

One binary, two plugin names. kubectl resolves plugins by `kubectl-<name>` on `$PATH`, so locally:

```sh
ln -s ~/.local/bin/kubectl-portscan ~/.local/bin/kubectl-nmap
```

Help text adapts to whichever name was used (derived from `argv[0]`).
The scan namespaces are always labelled `managed-by=kubectl-portscan`, so
`cleanup` from either name finds them.

For Krew, `krew/portscan.yaml` and `krew/nmap.yaml` are separate plugin entries
pointing at separate archives (each containing a binary named after its plugin).
`scripts/dist.sh` builds all archives from one compile and prints checksums.

## Examples

```sh
# Open ports on a host, as seen from the pod network (no extra caps needed)
kubectl portscan 10.0.0.5 --scan-type connect

# All TCP ports on a host, from a specific node's own network namespace
kubectl portscan 10.0.0.5 --from-node worker-2 --host-network -p-

# A whole range, JSON output
kubectl portscan 10.0.0.0/24 -o json

# Leftovers after a crash or --keep
kubectl portscan cleanup --older-than 0
```

Exit codes: `0` ok, `1` error.

Targets are literal IPs or CIDRs. `--from-node` pins where the scanner pod runs,
not what it scans.

## Guardrails

- Targets must be private/loopback/link-local/CGNAT IPs or ranges unless `--allow-external`.
- CIDRs larger than /16 need `--force`.
- Scanner pod has no service-account token, drops all capabilities except `NET_RAW`/`NET_ADMIN` (none for `--scan-type connect`), and has an `activeDeadlineSeconds` equal to `--timeout`.
- Container script passes targets/flags as argv (`"$@"`), never interpolated into a shell string.

## RBAC needed

```yaml
rules:
- apiGroups: [""]
  resources: [namespaces]
  verbs: [create, delete, list]
- apiGroups: [""]
  resources: [pods]
  verbs: [create, get, list, delete]
- apiGroups: [""]
  resources: [pods/log]
  verbs: [get]
- apiGroups: [""]
  resources: [nodes]
  verbs: [get]   # only for validating --from-node
```

Anyone who can create namespaces + privileged pods effectively has node-level access, so treat this role like cluster-admin.

## Caveats / TODO

- Not yet compiled or tested against a live cluster; expect a compile fix or two.
- Default image is `instrumentisto/nmap:latest`; pin by digest or mirror it internally. Air-gapped clusters need `--image`.
- Admission policies other than PodSecurity (Kyverno, Gatekeeper, VAP) may still block the pod.
- UDP scans are slow and report `open|filtered` often.
- Scope is deliberately narrow: scan literal IPs/CIDRs. No `--expect`, no `nodes`/`svc:` target resolution.
