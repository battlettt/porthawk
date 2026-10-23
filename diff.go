package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
)

// DiffReport compares two scans of the same targets.
type DiffReport struct {
	OpenedCount    int          `json:"opened_count"`
	ClosedCount    int          `json:"closed_count"`
	ChangedCount   int          `json:"changed_count"`
	UnchangedCount int          `json:"unchanged_count"`
	Opened         []Result     `json:"opened"`  // open now, not before
	Closed         []Result     `json:"closed"`  // open before, not now
	Changed        []PortChange `json:"changed"` // open in both, but different
}

// PortChange describes a port that was open in both scans but whose
// service, version, banner or TLS details differ.
type PortChange struct {
	Host    netip.Addr    `json:"host"`
	Port    int           `json:"port"`
	Service string        `json:"service"` // as of the new scan
	Changes []FieldChange `json:"changes"`
}

// FieldChange is one field that differs between two scans. Field uses the
// json output names (service, banner, tls_version, ...).
type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// portKey identifies a result across scans.
type portKey struct {
	host netip.Addr
	port int
}

func keyOf(r Result) portKey { return portKey{r.Host, r.Port} }

// LoadScan reads results from a file written by porthawk's json output:
// either the bare results array or the object with "results" and "diff"
// written when -diff is used.
func LoadScan(path string) ([]Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	results, err := parseScan(data)
	if err != nil {
		return nil, fmt.Errorf("%s is not a porthawk json scan: %w", path, err)
	}
	return results, nil
}

// parseScan decodes json scan output.
func parseScan(data []byte) ([]Result, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("file is empty")
	}
	var results []Result
	switch data[0] {
	case '[':
		if err := json.Unmarshal(data, &results); err != nil {
			return nil, err
		}
	case '{':
		var report struct {
			Results *[]Result `json:"results"`
		}
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, err
		}
		if report.Results == nil {
			return nil, errors.New(`object has no "results" array`)
		}
		results = *report.Results
	default:
		return nil, errors.New("expected a json array or object")
	}
	return results, nil
}

// DiffScans compares an earlier scan with a later one, matching results by
// host and port. The lists in the report are sorted by host, then port.
func DiffScans(old, new []Result) DiffReport {
	before := make(map[portKey]Result, len(old))
	for _, r := range old {
		before[keyOf(r)] = r
	}
	after := make(map[portKey]bool, len(new))
	d := DiffReport{Opened: []Result{}, Closed: []Result{}, Changed: []PortChange{}}
	for _, r := range new {
		after[keyOf(r)] = true
		prev, ok := before[keyOf(r)]
		if !ok {
			d.Opened = append(d.Opened, r)
			continue
		}
		if changes := compareFields(prev, r); len(changes) > 0 {
			d.Changed = append(d.Changed, PortChange{r.Host, r.Port, r.Service, changes})
		} else {
			d.UnchangedCount++
		}
	}
	for _, r := range old {
		if !after[keyOf(r)] {
			d.Closed = append(d.Closed, r)
			after[keyOf(r)] = true // report duplicates once
		}
	}
	slices.SortFunc(d.Opened, compareResults)
	slices.SortFunc(d.Closed, compareResults)
	slices.SortFunc(d.Changed, func(a, b PortChange) int {
		return compareResults(Result{Host: a.Host, Port: a.Port}, Result{Host: b.Host, Port: b.Port})
	})
	d.OpenedCount, d.ClosedCount, d.ChangedCount = len(d.Opened), len(d.Closed), len(d.Changed)
	return d
}

// compareFields lists the fields that differ between two results for the
// same port. A missing TLS handshake compares as empty TLS fields.
func compareFields(old, new Result) []FieldChange {
	var oldTLS, newTLS TLSInfo
	if old.TLS != nil {
		oldTLS = *old.TLS
	}
	if new.TLS != nil {
		newTLS = *new.TLS
	}
	var changes []FieldChange
	for _, f := range []FieldChange{
		{"service", old.Service, new.Service},
		{"version", old.Version, new.Version},
		{"banner", old.Banner, new.Banner},
		{"tls_version", oldTLS.Version, newTLS.Version},
		{"tls_cipher", oldTLS.Cipher, newTLS.Cipher},
		{"tls_cert_subject", oldTLS.CertSubject, newTLS.CertSubject},
	} {
		if f.Old != f.New {
			changes = append(changes, f)
		}
	}
	return changes
}

// InScope returns the results whose host and port are both among those
// given, so that a previous scan can be compared with a narrower one
// without reporting the unscanned ports as closed.
func InScope(results []Result, hosts []netip.Addr, ports []int) []Result {
	hostSet := make(map[netip.Addr]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}
	portSet := make(map[int]bool, len(ports))
	for _, p := range ports {
		portSet[p] = true
	}
	var out []Result
	for _, r := range results {
		if hostSet[r.Host] && portSet[r.Port] {
			out = append(out, r)
		}
	}
	return out
}

// WriteDiffSummary writes a human-readable summary of d, which compares the
// scan in the file named from with the current one.
func WriteDiffSummary(w io.Writer, d DiffReport, from string) error {
	if d.OpenedCount+d.ClosedCount+d.ChangedCount == 0 {
		_, err := fmt.Fprintf(w, "No changes since %s (%d port(s) unchanged).\n", from, d.UnchangedCount)
		return err
	}
	fmt.Fprintf(w, "Changes since %s: %d opened, %d closed, %d changed, %d unchanged\n",
		from, d.OpenedCount, d.ClosedCount, d.ChangedCount, d.UnchangedCount)

	type line struct{ mark, addr, service, banner string }
	var lines []line
	for _, r := range d.Opened {
		lines = append(lines, line{"+ opened", diffAddr(r.Host, r.Port), r.serviceColumn(), r.Banner})
	}
	for _, r := range d.Closed {
		lines = append(lines, line{"- closed", diffAddr(r.Host, r.Port), r.serviceColumn(), r.Banner})
	}
	addrWidth, serviceWidth := 0, 0
	for _, c := range d.Changed {
		addrWidth = max(addrWidth, len(diffAddr(c.Host, c.Port)))
	}
	for _, l := range lines {
		addrWidth, serviceWidth = max(addrWidth, len(l.addr)), max(serviceWidth, len(l.service))
	}
	for _, l := range lines {
		fmt.Fprintf(w, "  %s  %-*s  %-*s  %s\n", l.mark, addrWidth, l.addr, serviceWidth, l.service, l.banner)
	}
	for _, c := range d.Changed {
		fmt.Fprintf(w, "  ~ changed %-*s  %s\n", addrWidth, diffAddr(c.Host, c.Port), c.Service)
		for _, f := range c.Changes {
			fmt.Fprintf(w, "      %s: %s -> %s\n", f.Field, quoteOrNone(f.Old), quoteOrNone(f.New))
		}
	}
	return nil
}

// diffAddr formats a host and port for the diff summary.
func diffAddr(h netip.Addr, port int) string {
	return netip.AddrPortFrom(h, uint16(port)).String()
}

// quoteOrNone quotes s for the diff summary, showing empty values as (none).
func quoteOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return strconv.Quote(s)
}
