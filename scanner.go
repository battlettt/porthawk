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
}

// Scanner performs concurrent TCP connect scans.
type Scanner struct {
	Workers int           // maximum concurrent connections
	Timeout time.Duration // dial timeout per connection
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

// probe connects to a single host/port and, if open, grabs its banner.
func (s *Scanner) probe(ctx context.Context, j job) (Result, bool) {
	addr := net.JoinHostPort(j.host.String(), strconv.Itoa(j.port))
	d := net.Dialer{Timeout: s.Timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, false
	}
	latency := time.Since(start)
	defer conn.Close()

	raw := GrabBanner(conn, j.host.String(), j.port, min(s.Timeout, time.Second))
	return Result{
		Host:    j.host,
		Port:    j.port,
		Service: GuessService(raw, j.port),
		Banner:  CleanBanner(raw, bannerLen),
		Latency: latency,
	}, true
}
