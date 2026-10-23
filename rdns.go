package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Reverse DNS defaults for -rdns.
const (
	rdnsWorkers = 16              // concurrent PTR lookups
	rdnsTimeout = 2 * time.Second // per-host lookup timeout
)

// ReverseResolver looks up the names for an address. It matches the
// signature of net.Resolver.LookupAddr so tests can substitute a fake.
type ReverseResolver func(ctx context.Context, addr string) ([]string, error)

// DefaultReverseResolver performs PTR lookups using the system resolver.
func DefaultReverseResolver(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

// LookupHostname returns the first name lookup finds for addr, without the
// trailing dot, or "" if the lookup fails or takes longer than timeout.
func LookupHostname(ctx context.Context, addr netip.Addr, lookup ReverseResolver, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	names, err := lookup(ctx, addr.String())
	if err != nil {
		return ""
	}
	for _, n := range names {
		if n = strings.TrimSuffix(n, "."); n != "" {
			return n
		}
	}
	return ""
}

// ResolveHostnames sets the Hostname of each result, looking up every
// distinct host once with a pool of workers. Hosts not yet looked up when
// ctx is cancelled keep an empty Hostname.
func ResolveHostnames(ctx context.Context, results []Result, lookup ReverseResolver, workers int, timeout time.Duration) {
	var hosts []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, r := range results {
		if !seen[r.Host] {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}

	jobs := make(chan netip.Addr)
	var mu sync.Mutex
	names := make(map[netip.Addr]string, len(hosts))
	var wg sync.WaitGroup
	for range min(max(workers, 1), len(hosts)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				if name := LookupHostname(ctx, h, lookup, timeout); name != "" {
					mu.Lock()
					names[h] = name
					mu.Unlock()
				}
			}
		}()
	}
feed:
	for _, h := range hosts {
		select {
		case jobs <- h:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	for i := range results {
		results[i].Hostname = names[results[i].Host]
	}
}
