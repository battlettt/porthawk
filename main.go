// Command porthawk is a fast concurrent TCP port scanner with service
// banner grabbing. Only scan systems you own or are authorized to test.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// Exit codes.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitInterrupted = 130
)

// defaultTop is the number of common ports scanned when no ports are given.
const defaultTop = 100

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("porthawk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		targets = fs.String("t", "", "targets: IPs, hostnames, CIDRs, ranges (comma-separated, required)")
		portStr = fs.String("p", "", "ports: e.g. 22,80,443 or 1-1024 (default: top 100)")
		workers = fs.Int("w", 100, "number of concurrent workers")
		timeout = fs.Duration("timeout", 2*time.Second, "per-connection dial timeout")
		outFile = fs.String("o", "", "write results to `file` instead of stdout")
		format  = fs.String("f", "table", "output format: table, json, csv, html")
		quiet   = fs.Bool("q", false, "suppress progress and summary messages")
		top     = fs.Int("top", 0, "scan the `N` most common ports")
		noTLS   = fs.Bool("notls", false, "skip TLS handshakes on TLS ports (443, 993, ...)")
		diff    = fs.String("diff", "", "compare results with a previous json scan in `file`")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: porthawk -t TARGETS [-p PORTS | -top N] [options]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "porthawk: "+format+"\n", a...)
		fs.Usage()
		return exitUsage
	}
	switch {
	case fs.NArg() > 0:
		return usage("unexpected arguments: %v", fs.Args())
	case *targets == "":
		return usage("-t is required")
	case *portStr != "" && *top > 0:
		return usage("use either -p or -top, not both")
	case *workers < 1:
		return usage("-w must be at least 1")
	case *timeout <= 0:
		return usage("-timeout must be positive")
	case !slices.Contains([]string{"table", "json", "csv", "html"}, *format):
		return usage("-f must be table, json, csv or html")
	case *diff != "" && *format != "json" && sameFile(*diff, *outFile):
		return usage("-o %s would replace the -diff file with %s output; add -f json to keep it comparable", *outFile, *format)
	}

	var ports []int
	var err error
	switch {
	case *portStr != "":
		ports, err = ParsePorts(*portStr)
	case *top > 0:
		ports, err = TopPorts(*top)
	default:
		ports, err = TopPorts(defaultTop)
	}
	if err != nil {
		return usage("%v", err)
	}

	// Read the previous scan before scanning, so a bad path fails fast and
	// "-diff scan.json -o scan.json" compares against last run's results.
	var previous []Result
	if *diff != "" {
		if previous, err = LoadScan(*diff); err != nil {
			fmt.Fprintf(stderr, "porthawk: -diff: could not read previous scan: %v\n", err)
			return exitError
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hosts, err := ParseTargets(ctx, *targets, DefaultResolver)
	if err != nil {
		return usage("%v", err)
	}

	logf := func(format string, a ...any) {
		if !*quiet {
			fmt.Fprintf(stderr, format+"\n", a...)
		}
	}
	logf("porthawk: scanning %d host(s) x %d port(s) with %d workers", len(hosts), len(ports), *workers)

	start := time.Now()
	s := &Scanner{Workers: *workers, Timeout: *timeout, NoTLS: *noTLS}
	var results []Result
	for r := range s.Scan(ctx, hosts, ports) {
		results = append(results, r)
	}
	finished := time.Now()
	interrupted := ctx.Err() != nil
	slices.SortFunc(results, compareResults)

	meta := ScanMeta{Targets: *targets, PortsScanned: len(ports), StartedAt: start, FinishedAt: finished}
	if *diff != "" {
		d := DiffScans(InScope(previous, hosts, ports), results)
		meta.Diff = &d
	}
	if err := writeOutput(*outFile, stdout, results, *format, meta); err != nil {
		fmt.Fprintf(stderr, "porthawk: writing results: %v\n", err)
		return exitError
	}
	if meta.Diff != nil {
		if interrupted {
			logf("porthawk: scan was interrupted; ports listed as closed may not have been probed")
		}
		// Keep json on stdout parseable: it already carries the diff, so
		// the summary goes to stderr there instead.
		w := stdout
		if *format == "json" && *outFile == "" {
			w = io.Discard
			if !*quiet {
				w = stderr
			}
		} else if *outFile == "" {
			fmt.Fprintln(w)
		}
		if err := WriteDiffSummary(w, *meta.Diff, *diff); err != nil {
			fmt.Fprintf(stderr, "porthawk: writing diff: %v\n", err)
			return exitError
		}
	}

	if interrupted {
		logf("porthawk: interrupted; %d open port(s) found before stopping", len(results))
		return exitInterrupted
	}
	logf("porthawk: %d open port(s) found in %s", len(results), finished.Sub(start).Round(time.Millisecond))
	return exitOK
}

// writeOutput writes results to path, or to stdout if path is empty.
func writeOutput(path string, stdout io.Writer, results []Result, format string, meta ScanMeta) error {
	if path == "" {
		return WriteResultsMeta(stdout, results, format, meta)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := WriteResultsMeta(f, results, format, meta); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// sameFile reports whether paths a and b name the same file.
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ai, aerr := os.Stat(a)
	bi, berr := os.Stat(b)
	if aerr == nil && berr == nil {
		return os.SameFile(ai, bi)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
