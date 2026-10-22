package main

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePorts expands a port spec such as "22,80,8000-8100" into a
// deduplicated, order-preserving list of ports in the range 1-65535.
func ParsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		start, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		end := start
		if isRange {
			if end, err = parsePort(hi); err != nil {
				return nil, err
			}
			if end < start {
				return nil, fmt.Errorf("port range %q is reversed", part)
			}
		}
		for p := start; p <= end; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	return out, nil
}

// TopPorts returns the n most common TCP ports.
func TopPorts(n int) ([]int, error) {
	if n < 1 || n > len(topPorts) {
		return nil, fmt.Errorf("-top must be between 1 and %d", len(topPorts))
	}
	return append([]int(nil), topPorts[:n]...), nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q (must be 1-65535)", s)
	}
	return p, nil
}
