package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"text/tabwriter"
	"time"
)

// jsonResult is the serialized form of a Result.
type jsonResult struct {
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Service   string   `json:"service"`
	Banner    string   `json:"banner"`
	LatencyMS float64  `json:"latency_ms"`
	TLS       *TLSInfo `json:"tls,omitempty"`
}

// ScanMeta describes the scan that produced a set of results. Formats that
// have nowhere to put it (table, json, csv) ignore it.
type ScanMeta struct {
	Targets      string // target spec as given on the command line
	PortsScanned int    // number of ports probed on each host
	StartedAt    time.Time
	FinishedAt   time.Time
}

// latencyMS returns the result's latency in milliseconds, rounded to 0.01.
func (r Result) latencyMS() float64 {
	return math.Round(float64(r.Latency.Microseconds())/10) / 100
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
		return writeJSON(w, results)
	case "csv":
		return writeCSV(w, results)
	case "html":
		return writeHTML(w, results, meta)
	}
	return fmt.Errorf("unknown format %q", format)
}

func writeTable(w io.Writer, results []Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPORT\tSERVICE\tTLS\tLATENCY\tBANNER")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%.2fms\t%s\n", r.Host, r.Port, r.Service, tlsColumn(r.TLS), r.latencyMS(), r.Banner)
	}
	return tw.Flush()
}

func writeJSON(w io.Writer, results []Result) error {
	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		out = append(out, jsonResult{r.Host.String(), r.Port, r.Service, r.Banner, r.latencyMS(), r.TLS})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeCSV(w io.Writer, results []Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"host", "port", "service", "banner", "latency_ms",
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
			r.Host.String(), strconv.Itoa(r.Port), r.Service, r.Banner,
			strconv.FormatFloat(r.latencyMS(), 'f', 2, 64),
			version, cipher, subject, expiry,
		})
	}
	cw.Flush()
	return cw.Error()
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
