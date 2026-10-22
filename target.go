package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// maxHosts caps how many addresses a single target spec may expand to,
// guarding against accidental scans of huge networks (e.g. a /8).
const maxHosts = 65536

// Resolver looks up the IP addresses for a hostname. It matches the
// signature of net.Resolver.LookupNetIP so tests can substitute a fake.
type Resolver func(ctx context.Context, network, host string) ([]netip.Addr, error)

// ParseTargets expands a comma-separated target spec into a deduplicated,
// order-preserving list of IP addresses. Each element may be a single IPv4
// or IPv6 address, a CIDR block, a dash range (10.0.0.1-10.0.0.20), or a
// hostname, which is resolved with resolve.
func ParseTargets(ctx context.Context, spec string, resolve Resolver) ([]netip.Addr, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, fmt.Errorf("no targets given")
	}
	seen := make(map[netip.Addr]bool)
	var out []netip.Addr
	add := func(a netip.Addr) {
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addrs, err := expandTarget(ctx, part, resolve)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			add(a)
		}
		if len(out) > maxHosts {
			return nil, fmt.Errorf("targets expand to more than %d hosts", maxHosts)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets given")
	}
	return out, nil
}

// expandTarget handles a single element of a target spec.
func expandTarget(ctx context.Context, s string, resolve Resolver) ([]netip.Addr, error) {
	if strings.Contains(s, "/") {
		return expandCIDR(s)
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return []netip.Addr{addr}, nil
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		start, err1 := netip.ParseAddr(lo)
		end, err2 := netip.ParseAddr(hi)
		if err1 == nil && err2 == nil {
			return expandRange(start, end)
		}
		// Hostnames may legitimately contain dashes; fall through unless
		// the left side was clearly an address.
		if err1 == nil {
			return nil, fmt.Errorf("invalid range %q", s)
		}
	}
	if !validHostname(s) {
		return nil, fmt.Errorf("invalid target %q", s)
	}
	if resolve == nil {
		return nil, fmt.Errorf("cannot resolve %q: no resolver", s)
	}
	addrs, err := resolve(ctx, "ip", s)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", s, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", s)
	}
	return addrs, nil
}

// expandCIDR returns every address in a prefix. For IPv4 blocks larger than
// a /31 the network and broadcast addresses are skipped.
func expandCIDR(s string) ([]netip.Addr, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q", s)
	}
	p = p.Masked()
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDR %q is too large (max %d hosts)", s, maxHosts)
	}
	var out []netip.Addr
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if p.Addr().Is4() && hostBits > 1 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

// expandRange returns all addresses from start to end inclusive.
func expandRange(start, end netip.Addr) ([]netip.Addr, error) {
	if start.Is4() != end.Is4() {
		return nil, fmt.Errorf("range %s-%s mixes address families", start, end)
	}
	if end.Less(start) {
		return nil, fmt.Errorf("range %s-%s is reversed", start, end)
	}
	var out []netip.Addr
	for a := start; ; a = a.Next() {
		out = append(out, a)
		if a == end {
			break
		}
		if len(out) >= maxHosts {
			return nil, fmt.Errorf("range %s-%s is too large (max %d hosts)", start, end, maxHosts)
		}
	}
	return out, nil
}

// validHostname performs a light RFC 1123 syntax check. An all-numeric
// final label is rejected so malformed IPs like 10.0.0.300 are not resolved.
func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(s, "."), ".")
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// DefaultResolver resolves hostnames using the system resolver.
func DefaultResolver(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}
