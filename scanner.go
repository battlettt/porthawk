package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Result describes a single open port.
type Result struct {
	Host    netip.Addr
	Port    int
	Service string
	Banner  string
	Latency time.Duration
	TLS     *TLSInfo // nil unless a TLS handshake succeeded
}

// Scanner performs concurrent TCP connect scans.
type Scanner struct {
	Workers int           // maximum concurrent connections
	Timeout time.Duration // dial timeout per connection
	NoTLS   bool          // skip TLS handshakes on TLS ports
}

// bannerLen is the maximum displayed banner length.
const bannerLen = 60

type job struct {
	host netip.Addr
	port int
}

// Scan probes every host/port pair and streams open ports on the returned
// channel, which is closed when the scan finishes or ctx is cancelled.
// Closed and filtered ports are not reported.
func (s *Scanner) Scan(ctx context.Context, hosts []netip.Addr, ports []int) <-chan Result {
	jobs := make(chan job)
	results := make(chan Result)

	go func() {
		defer close(jobs)
		for _, h := range hosts {
			for _, p := range ports {
				select {
				case jobs <- job{h, p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for range max(s.Workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r, ok := s.probe(ctx, j)
				if !ok {
					continue
				}
				select {
				case results <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

// probe connects to a single host/port and, if open, grabs its banner. On
// TLS ports the banner is read over TLS when the handshake succeeds;
// otherwise porthawk reconnects and falls back to a plaintext probe.
func (s *Scanner) probe(ctx context.Context, j job) (Result, bool) {
	addr := net.JoinHostPort(j.host.String(), strconv.Itoa(j.port))
	d := net.Dialer{Timeout: s.Timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, false
	}
	r := Result{Host: j.host, Port: j.port, Latency: time.Since(start)}
	defer func() { conn.Close() }()

	if _, ok := tlsPorts[j.port]; ok && !s.NoTLS {
		tc, info, err := ProbeTLS(conn, j.host.String(), s.Timeout)
		if err == nil {
			conn, r.TLS = tc, &info
		} else {
			// The failed handshake has consumed the connection.
			conn.Close()
			plain, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				r.Service = GuessService(nil, j.port)
				return r, true
			}
			conn = plain
		}
	}

	raw := GrabBanner(conn, j.host.String(), j.port, min(s.Timeout, time.Second))
	r.Service = GuessService(raw, j.port)
	if r.TLS != nil {
		r.Service = tlsService(r.Service, j.port)
	}
	r.Banner = CleanBanner(raw, bannerLen)
	return r, true
}
