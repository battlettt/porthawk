package main

import (
	"context"
	"net/netip"
	"testing"
	"unicode"
)

// FuzzParsePorts checks that port specs never panic and that a successful
// parse always yields a deduplicated list of ports in range 1-65535.
func FuzzParsePorts(f *testing.F) {
	f.Add("22,80,443")
	f.Add("1-1024")
	f.Add("22, 80 , 443")
	f.Add("")
	f.Add("0")
	f.Add("65536")
	f.Add("100-1")
	f.Add("22,,80")
	f.Add("22-22")
	f.Add("1-65535")
	f.Add("abc")
	f.Add("22-")
	f.Add("-80")
	f.Add("99999999999999999999")
	f.Fuzz(func(t *testing.T, spec string) {
		ports, err := ParsePorts(spec)
		if err != nil {
			return
		}
		if len(ports) == 0 {
			t.Fatalf("ParsePorts(%q) succeeded with no ports", spec)
		}
		seen := make(map[int]bool)
		for _, p := range ports {
			if p < 1 || p > 65535 {
				t.Fatalf("ParsePorts(%q) returned out-of-range port %d", spec, p)
			}
			if seen[p] {
				t.Fatalf("ParsePorts(%q) returned duplicate port %d", spec, p)
			}
			seen[p] = true
		}
	})
}

// FuzzParseTargets checks that target specs never panic and that a
// successful parse yields a deduplicated, bounded list of addresses.
// It reuses the fakeResolver from target_test.go, so no test touches
// the network.
func FuzzParseTargets(f *testing.F) {
	f.Add("127.0.0.1")
	f.Add("10.0.0.0/24")
	f.Add("10.0.0.1-10.0.0.20")
	f.Add("web.example.test")
	f.Add("::1")
	f.Add("2001:db8::/126")
	f.Add("")
	f.Add("10.0.0.300")
	f.Add("10.0.0.0/8")
	f.Add("256.256.256.256")
	f.Add("a-b-c")
	f.Add("10.0.0.1-10.0.0.1")
	f.Add("host_name!")
	f.Add("10.0.0.1,10.0.0.1,10.0.0.2")
	f.Fuzz(func(t *testing.T, spec string) {
		addrs, err := ParseTargets(context.Background(), spec, fakeResolver)
		if err != nil {
			return
		}
		if len(addrs) == 0 {
			t.Fatalf("ParseTargets(%q) succeeded with no addresses", spec)
		}
		if len(addrs) > maxHosts {
			t.Fatalf("ParseTargets(%q) returned %d addresses, over the %d cap", spec, len(addrs), maxHosts)
		}
		seen := make(map[netip.Addr]bool)
		for _, a := range addrs {
			if seen[a] {
				t.Fatalf("ParseTargets(%q) returned duplicate address %s", spec, a)
			}
			seen[a] = true
		}
	})
}

// FuzzCleanBanner checks that cleaned banners never contain control
// characters and never exceed the requested length.
func FuzzCleanBanner(f *testing.F) {
	f.Add([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"))
	f.Add([]byte("\x00\x01hi\x7f there"))
	f.Add([]byte("\u009b31mred\u0085"))
	f.Add([]byte{})
	f.Add([]byte("\xff\xfe\x00binary\x80\x9f"))
	f.Add([]byte("a very long banner that should be truncated to the limit"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		const max = 60
		out := CleanBanner(raw, max)
		if len([]rune(out)) > max {
			t.Fatalf("CleanBanner(%q) returned %d runes, over the %d limit", raw, len([]rune(out)), max)
		}
		for _, r := range out {
			if unicode.IsControl(r) {
				t.Fatalf("CleanBanner(%q) returned control rune U+%04X in %q", raw, r, out)
			}
		}
	})
}
