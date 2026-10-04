package main

import (
	"context"
	"fmt"
	"net/netip"

	"k8s.io/client-go/kubernetes"
)

// resolveTargets validates the literal IP/CIDR targets and returns them in the
// form handed to nmap. The kubernetes client is accepted for symmetry with
// future target kinds but is currently unused.
func resolveTargets(_ context.Context, _ kubernetes.Interface, targets []string, allowExternal, force bool) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets given")
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		switch {
		case isCIDR(t):
			p, err := netip.ParsePrefix(t)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", t, err)
			}
			if !allowExternal && !isPrivateAddr(p.Addr()) {
				return nil, fmt.Errorf("%q is not a private/cluster range; pass --allow-external to scan it", t)
			}
			if bits := p.Bits(); p.Addr().Is4() && bits < 16 && !force {
				return nil, fmt.Errorf("%q is larger than /16 (%d hosts); pass --force", t, 1<<(32-bits))
			}
			out = append(out, p.String())
		default:
			addr, err := netip.ParseAddr(t)
			if err != nil {
				return nil, fmt.Errorf("invalid IP %q (only IPs and CIDRs are supported): %w", t, err)
			}
			if !allowExternal && !isPrivateAddr(addr) {
				return nil, fmt.Errorf("%q is not a private/cluster IP; pass --allow-external to scan it", t)
			}
			out = append(out, addr.String())
		}
	}
	return out, nil
}

func isCIDR(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}

// isPrivateAddr reports whether addr is in a range we consider safe to scan
// without --allow-external: RFC1918, loopback, link-local, CGNAT (100.64/10),
// unique-local IPv6, plus unspecified.
func isPrivateAddr(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsPrivate() || addr.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10 (CGNAT) is not covered by netip.Addr.IsPrivate.
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 100 && b[1]&0xc0 == 0x40 {
			return true
		}
	}
	return false
}
