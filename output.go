package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"text/tabwriter"
)

// jsonResult is the serialized form of a Result.
type jsonResult struct {
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	Service   string  `json:"service"`
	Banner    string  `json:"banner"`
	LatencyMS float64 `json:"latency_ms"`
}

// latencyMS returns the result's latency in milliseconds, rounded to 0.01.
func (r Result) latencyMS() float64 {
	return math.Round(float64(r.Latency.Microseconds())/10) / 100
}

// WriteResults renders results to w in the given format: table, json or csv.
func WriteResults(w io.Writer, results []Result, format string) error {
	switch format {
	case "table":
		return writeTable(w, results)
	case "json":
		return writeJSON(w, results)
	case "csv":
		return writeCSV(w, results)
	}
	return fmt.Errorf("unknown format %q", format)
}

func writeTable(w io.Writer, results []Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPORT\tSERVICE\tLATENCY\tBANNER")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%.2fms\t%s\n", r.Host, r.Port, r.Service, r.latencyMS(), r.Banner)
	}
	return tw.Flush()
}

func writeJSON(w io.Writer, results []Result) error {
	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		out = append(out, jsonResult{r.Host.String(), r.Port, r.Service, r.Banner, r.latencyMS()})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeCSV(w io.Writer, results []Result) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"host", "port", "service", "banner", "latency_ms"})
	for _, r := range results {
		_ = cw.Write([]string{
			r.Host.String(), strconv.Itoa(r.Port), r.Service, r.Banner,
			strconv.FormatFloat(r.latencyMS(), 'f', 2, 64),
		})
	}
	cw.Flush()
	return cw.Error()
}
