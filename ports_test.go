package main

import (
	"slices"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		spec string
		want []int
	}{
		{"80", []int{80}},
		{"22,80,443", []int{22, 80, 443}},
		{"1-5", []int{1, 2, 3, 4, 5}},
		{"443, 20-22 ,80", []int{443, 20, 21, 22, 80}},
		{"80,80,79-81", []int{80, 79, 81}},
		{"65535", []int{65535}},
	}
	for _, tt := range tests {
		got, err := ParsePorts(tt.spec)
		if err != nil {
			t.Errorf("ParsePorts(%q): %v", tt.spec, err)
			continue
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
		}
	}
	if got, _ := ParsePorts("1-1024"); len(got) != 1024 {
		t.Errorf("1-1024: got %d ports", len(got))
	}
}

func TestParsePortsInvalid(t *testing.T) {
	for _, spec := range []string{"", ",", "0", "65536", "-1", "abc", "80-", "100-90", "1-70000", "22;80"} {
		if got, err := ParsePorts(spec); err == nil {
			t.Errorf("ParsePorts(%q) = %v, expected error", spec, got)
		}
	}
}

func TestTopPorts(t *testing.T) {
	got, err := TopPorts(5)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []int{80, 23, 443, 21, 22}) {
		t.Errorf("TopPorts(5) = %v", got)
	}
	all, err := TopPorts(len(topPorts))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, p := range all {
		if p < 1 || p > 65535 || seen[p] {
			t.Errorf("top ports list has invalid or duplicate port %d", p)
		}
		seen[p] = true
	}
	for _, n := range []int{0, -1, len(topPorts) + 1} {
		if _, err := TopPorts(n); err == nil {
			t.Errorf("TopPorts(%d): expected error", n)
		}
	}
}
