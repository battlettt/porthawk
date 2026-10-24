package main

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// TestScanRateLimit checks that Rate throttles connection attempts: 10
// probes at 20 per second must take at least ~350ms of dispatch time, and
// the scan must still run to completion. Ports on loopback in the 61000
// range are expected to be closed; even if one is open, dispatch pacing
// still dominates the elapsed time.
func TestScanRateLimit(t *testing.T) {
	ports := []int{61000, 61001, 61002, 61003, 61004, 61005, 61006, 61007, 61008, 61009}
	s := &Scanner{Workers: 10, Timeout: 500 * time.Millisecond, Rate: 20}
	start := time.Now()
	for range s.Scan(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ports) {
	}
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Errorf("rate-limited scan of %d probes at 20/s took %s, want at least 350ms", len(ports), elapsed)
	}
}

// TestScanUnlimitedRate checks that a zero Rate does not pace the scan:
// 10 probes must finish well inside a second.
func TestScanUnlimitedRate(t *testing.T) {
	ports := []int{61000, 61001, 61002, 61003, 61004, 61005, 61006, 61007, 61008, 61009}
	s := &Scanner{Workers: 10, Timeout: 500 * time.Millisecond, Rate: 0}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	for range s.Scan(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ports) {
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("unlimited scan took %s, want under 2s", elapsed)
	}
}
