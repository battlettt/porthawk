package main

import (
	"cmp"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"text/tabwriter"
	"time"
)

// jsonResult is the serialized form of a Result.
type jsonResult struct {
	Host      string   `json:"host"`
	Hostname  string   `json:"hostname,omitempty"`
	Port      int      `json:"port"`
	Service   string   `json:"service"`
	Version   string   `json:"version,omitempty"`
	Banner    string   `json:"banner"`
	LatencyMS float64  `json:"latency_ms"`
	TLS       *TLSInfo `json:"tls,omitempty"`
}

// jsonReport is the json output when results are compared against a
// previous scan; without a comparison the output is the bare results array.
type jsonReport struct {
	Results []Result    `json:"results"`
	Diff    *DiffReport `json:"diff"`
}

// ScanMeta describes the scan that produced a set of results. The html
// report shows the scan details in its header and json output includes
// Diff; other formats ignore it.
type ScanMeta struct {
	Targets      string // target spec as given on the command line
	PortsScanned int    // number of ports probed on each host
	StartedAt    time.Time
	FinishedAt   time.Time
	Diff         *DiffReport // comparison with a previous scan, if any
}

// latencyMS returns the result's latency in milliseconds, rounded to 0.01.
func (r Result) latencyMS() float64 {
	return math.Round(float64(r.Latency.Microseconds())/10) / 100
}

// MarshalJSON encodes r in porthawk's json output format.
func (r Result) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonResult{r.Host.String(), r.Hostname, r.Port, r.Service, r.Version, r.Banner, r.latencyMS(), r.TLS})
}

// UnmarshalJSON decodes a result written by MarshalJSON. Unknown fields are
// ignored and missing ones left empty, except host and port, which are
// required.
func (r *Result) UnmarshalJSON(data []byte) error {
	var j jsonResult
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	host, err := netip.ParseAddr(j.Host)
	if err != nil {
		return fmt.Errorf("invalid host %q", j.Host)
	}
	if j.Port < 1 || j.Port > 65535 {
		return fmt.Errorf("invalid port %d for host %s", j.Port, j.Host)
	}
	*r = Result{
		Host:     host,
		Hostname: j.Hostname,
		Port:     j.Port,
		Service:  j.Service,
		Version:  j.Version,
		Banner:   j.Banner,
		Latency:  time.Duration(math.Round(j.LatencyMS*1000)) * time.Microsecond,
		TLS:      j.TLS,
	}
	return nil
}

// WriteResults renders results to w in the given format: table, json, csv
// or html. It is WriteResultsMeta without scan metadata.
func WriteResults(w io.Writer, results []Result, format string) error {
	return WriteResultsMeta(w, results, format, ScanMeta{})
}

// WriteResultsMeta renders results to w in the given format. The html
// report includes meta in its header; other formats ignore it.
func WriteResultsMeta(w io.Writer, results []Result, format string, meta ScanMeta) error {
	switch format {
	case "table":
		return writeTable(w, results)
	case "json":
		return writeJSON(w, results, meta.Diff)
	case "csv":
		return writeCSV(w, results)
	case "html":
		return writeHTML(w, results, meta)
	}
	return fmt.Errorf("unknown format %q", format)
}

// writeTable writes results as an aligned table. The HOSTNAME column is
// only included when at least one result has a hostname.
func writeTable(w io.Writer, results []Result) error {
	withHostname := slices.ContainsFunc(results, func(r Result) bool { return r.Hostname != "" })
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if withHostname {
		fmt.Fprint(tw, "HOST\tHOSTNAME\t")
	} else {
		fmt.Fprint(tw, "HOST\t")
	}
	fmt.Fprintln(tw, "PORT\tSERVICE\tTLS\tLATENCY\tBANNER")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t", r.Host)
		if withHostname {
			fmt.Fprintf(tw, "%s\t", cmp.Or(r.Hostname, "-"))
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%.2fms\t%s\n", r.Port, r.serviceColumn(), tlsColumn(r.TLS), r.latencyMS(), r.Banner)
	}
	return tw.Flush()
}

// writeJSON writes results as a json array, or, when diff is non-nil, as an
// object holding the results and the diff.
func writeJSON(w io.Writer, results []Result, diff *DiffReport) error {
	if results == nil {
		results = []Result{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if diff != nil {
		return enc.Encode(jsonReport{results, diff})
	}
	return enc.Encode(results)
}

func writeCSV(w io.Writer, results []Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"host", "hostname", "port", "service", "version", "banner", "latency_ms",
		"tls_version", "tls_cipher", "tls_cert_subject", "tls_cert_expiry",
	})
	for _, r := range results {
		var version, cipher, subject, expiry string
		if r.TLS != nil {
			version, cipher, subject = r.TLS.Version, r.TLS.Cipher, r.TLS.CertSubject
			if !r.TLS.CertNotAfter.IsZero() {
				expiry = r.TLS.CertNotAfter.UTC().Format(time.RFC3339)
			}
		}
		_ = cw.Write([]string{
			r.Host.String(), r.Hostname, strconv.Itoa(r.Port), r.Service, r.Version, r.Banner,
			strconv.FormatFloat(r.latencyMS(), 'f', 2, 64),
			version, cipher, subject, expiry,
		})
	}
	cw.Flush()
	return cw.Error()
}

// serviceColumn is the table's SERVICE cell: the service name, followed by
// the version in parentheses when known.
func (r Result) serviceColumn() string {
	if r.Version == "" {
		return r.Service
	}
	return r.Service + " (" + r.Version + ")"
}

// tlsColumn is the table's TLS cell: the short protocol version, with "!"
// appended when the certificate has expired, or "-" without TLS.
func tlsColumn(info *TLSInfo) string {
	if info == nil {
		return "-"
	}
	if info.CertExpired {
		return info.shortVersion() + "!"
	}
	return info.shortVersion()
}
