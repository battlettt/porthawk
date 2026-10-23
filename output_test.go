package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// sampleResults returns one plaintext and one TLS result with an expired
// certificate.
func sampleResults() []Result {
	expiry := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	return []Result{
		{
			Host: netip.MustParseAddr("10.0.0.1"), Port: 22, Service: "ssh",
			Banner: "SSH-2.0-OpenSSH_9.6", Latency: 1500 * time.Microsecond,
		},
		{
			Host: netip.MustParseAddr("10.0.0.1"), Port: 443, Service: "https",
			Banner: "HTTP/1.1 200 OK <script>alert(1)</script>", Latency: time.Millisecond,
			TLS: &TLSInfo{
				Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256",
				CertSubject: "web & co", CertNotAfter: expiry, CertExpired: true,
			},
		},
	}
}

func TestWriteTableTLS(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, sampleResults(), "table"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines:\n%s", len(lines), buf.String())
	}
	if f := strings.Fields(lines[0]); f[3] != "TLS" {
		t.Errorf("header = %q, want TLS as the fourth column", lines[0])
	}
	if f := strings.Fields(lines[1]); f[3] != "-" {
		t.Errorf("plaintext row TLS column = %q, want -", f[3])
	}
	if f := strings.Fields(lines[2]); f[3] != "1.3!" {
		t.Errorf("TLS row TLS column = %q, want 1.3!", f[3])
	}
}

func TestWriteJSONTLS(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, sampleResults(), "json"); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got[0]["tls"]; ok {
		t.Error("plaintext result has a tls key, want it omitted")
	}
	tlsObj, ok := got[1]["tls"].(map[string]any)
	if !ok {
		t.Fatalf("TLS result tls = %v, want an object", got[1]["tls"])
	}
	if tlsObj["version"] != "TLS 1.3" || tlsObj["cert_expired"] != true ||
		tlsObj["cert_not_after"] != "2024-01-02T03:04:05Z" {
		t.Errorf("tls object = %v", tlsObj)
	}
}

func TestWriteCSVTLS(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, sampleResults(), "csv"); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"host", "port", "service", "banner", "latency_ms", "tls_version", "tls_cipher", "tls_cert_subject", "tls_cert_expiry"},
		{"10.0.0.1", "22", "ssh", "SSH-2.0-OpenSSH_9.6", "1.50", "", "", "", ""},
		{"10.0.0.1", "443", "https", "HTTP/1.1 200 OK <script>alert(1)</script>", "1.00",
			"TLS 1.3", "TLS_AES_128_GCM_SHA256", "web & co", "2024-01-02T03:04:05Z"},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d", len(rows), len(want))
	}
	for i := range want {
		if strings.Join(rows[i], "|") != strings.Join(want[i], "|") {
			t.Errorf("row %d = %q, want %q", i, rows[i], want[i])
		}
	}
}

func TestWriteHTML(t *testing.T) {
	started := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	meta := ScanMeta{
		Targets:      "10.0.0.0/24,<evil>",
		PortsScanned: 100,
		StartedAt:    started,
		FinishedAt:   started.Add(1500 * time.Millisecond),
	}
	results := append(sampleResults(), Result{
		Host: netip.MustParseAddr("10.0.0.2"), Port: 2222, Service: "ssh",
	})
	var buf bytes.Buffer
	if err := WriteResultsMeta(&buf, results, "html", meta); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"10.0.0.0/24,&lt;evil&gt;",
		"<dd>100</dd>",
		"<dd>1.5s</dd>",
		"<dd>3</dd>",
		"<tr><td>ssh</td><td>2</td></tr>",
		"<tr><td>https</td><td>1</td></tr>",
		"TLS_AES_128_GCM_SHA256",
		"web &amp; co",
		"expires 2024-01-02",
		`<span class="warn">expired</span>`,
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"Scan finished at 2026-03-04 10:00:01 UTC",
		`href="https://github.com/battlettt/porthawk"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q", want)
		}
	}
	if strings.Contains(out, "<script>") || strings.Contains(out, "<evil>") {
		t.Error("report contains unescaped dynamic content")
	}
}

func TestWriteHTMLEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, nil, "html"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "No open ports found.") || strings.Contains(out, "<th>Banner</th>") {
		t.Errorf("empty report should have no results table:\n%s", out)
	}
	if strings.Contains(out, "Time taken") {
		t.Error("report without a start time shows a duration")
	}
}
