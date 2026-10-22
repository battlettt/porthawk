package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// fakeResolver resolves a fixed set of names without touching the network.
func fakeResolver(_ context.Context, _, host string) ([]netip.Addr, error) {
	switch host {
	case "web.example.test":
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	case "dual.example.test":
		return []netip.Addr{netip.MustParseAddr("10.0.0.6"), netip.MustParseAddr("2001:db8::6")}, nil
	}
	return nil, errors.New("no such host")
}

func parse(t *testing.T, spec string) []string {
	t.Helper()
	addrs, err := ParseTargets(context.Background(), spec, fakeResolver)
	if err != nil {
		t.Fatalf("ParseTargets(%q): %v", spec, err)
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

func TestParseTargetsCIDR(t *testing.T) {
	got := parse(t, "192.168.1.0/24")
	if len(got) != 254 || got[0] != "192.168.1.1" || got[253] != "192.168.1.254" {
		t.Errorf("/24: got %d hosts, first %s, last %s", len(got), got[0], got[len(got)-1])
	}
	if got := parse(t, "10.0.0.7/32"); len(got) != 1 || got[0] != "10.0.0.7" {
		t.Errorf("/32: got %v", got)
	}
	if got := parse(t, "10.0.0.0/31"); len(got) != 2 {
		t.Errorf("/31: got %v, want 2 hosts", got)
	}
	if got := parse(t, "192.168.1.77/30"); len(got) != 2 || got[0] != "192.168.1.77" {
		t.Errorf("unmasked /30: got %v", got)
	}
	if got := parse(t, "2001:db8::/126"); len(got) != 4 {
		t.Errorf("IPv6 /126: got %v, want 4 hosts", got)
	}
}

func TestParseTargetsRange(t *testing.T) {
	got := parse(t, "10.0.0.1-10.0.0.20")
	if len(got) != 20 || got[0] != "10.0.0.1" || got[19] != "10.0.0.20" {
		t.Errorf("range: got %v", got)
	}
	got = parse(t, "10.0.0.254-10.0.1.1")
	want := []string{"10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"}
	if !slices.Equal(got, want) {
		t.Errorf("octet-crossing range: got %v, want %v", got, want)
	}
}

func TestParseTargetsMixedAndDedupe(t *testing.T) {
	got := parse(t, "10.0.0.5, web.example.test,10.0.0.4-10.0.0.6,::ffff:10.0.0.4,dual.example.test,::1")
	want := []string{"10.0.0.5", "10.0.0.4", "10.0.0.6", "2001:db8::6", "::1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTargetsInvalid(t *testing.T) {
	for _, spec := range []string{
		"",
		" , ",
		"10.0.0.300",
		"10.0.0.0/33",
		"10.0.0.0/8",
		"10.0.0.20-10.0.0.1",
		"10.0.0.1-::1",
		"10.0.0.1-banana",
		"bad_host!",
		"-leading.dash",
		"unknown.example.test",
	} {
		if _, err := ParseTargets(context.Background(), spec, fakeResolver); err == nil {
			t.Errorf("ParseTargets(%q): expected error", spec)
		}
	}
}
