package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestLookupHostnameLoopback(t *testing.T) {
	// The name for 127.0.0.1 varies ("localhost", "localhost.localdomain",
	// the machine's own name), so only check that there is one.
	got := LookupHostname(context.Background(), netip.MustParseAddr("127.0.0.1"), DefaultReverseResolver, 2*time.Second)
	if got == "" {
		t.Error("LookupHostname(127.0.0.1) = \"\", want a name")
	}
}

func TestLookupHostname(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")
	tests := []struct {
		name   string
		lookup ReverseResolver
		want   string
	}{
		{"first name, trailing dot trimmed", func(context.Context, string) ([]string, error) {
			return []string{"web.example.test.", "alias.example.test."}, nil
		}, "web.example.test"},
		{"empty names skipped", func(context.Context, string) ([]string, error) {
			return []string{".", "web.example.test"}, nil
		}, "web.example.test"},
		{"no names", func(context.Context, string) ([]string, error) { return nil, nil }, ""},
		{"error", func(context.Context, string) ([]string, error) {
			return []string{"ignored.example.test"}, errors.New("no such host")
		}, ""},
		{"timeout", func(ctx context.Context, _ string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, ""},
	}
	for _, tt := range tests {
		if got := LookupHostname(context.Background(), addr, tt.lookup, 10*time.Millisecond); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestResolveHostnames(t *testing.T) {
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")
	results := []Result{{Host: a, Port: 22}, {Host: a, Port: 80}, {Host: b, Port: 22}, {Host: c, Port: 443}}

	var mu sync.Mutex
	calls := make(map[string]int)
	lookup := func(_ context.Context, addr string) ([]string, error) {
		mu.Lock()
		calls[addr]++
		mu.Unlock()
		switch addr {
		case "10.0.0.1":
			return []string{"a.example.test."}, nil
		case "10.0.0.2":
			return []string{"b.example.test."}, nil
		}
		return nil, errors.New("no such host")
	}
	ResolveHostnames(context.Background(), results, lookup, 4, time.Second)

	want := []string{"a.example.test", "a.example.test", "b.example.test", ""}
	for i, r := range results {
		if r.Hostname != want[i] {
			t.Errorf("results[%d].Hostname = %q, want %q", i, r.Hostname, want[i])
		}
	}
	for addr, n := range calls {
		if n != 1 {
			t.Errorf("%s looked up %d times, want once", addr, n)
		}
	}
	if len(calls) != 3 {
		t.Errorf("looked up %d hosts, want 3", len(calls))
	}
}

func TestResolveHostnamesCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := []Result{{Host: netip.MustParseAddr("10.0.0.1"), Port: 22}}
	lookup := func(ctx context.Context, _ string) ([]string, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []string{"a.example.test."}, nil
	}
	ResolveHostnames(ctx, results, lookup, 4, time.Second)
	if results[0].Hostname != "" {
		t.Errorf("Hostname = %q after cancellation, want empty", results[0].Hostname)
	}
}
