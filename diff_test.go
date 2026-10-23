package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// writeScan writes results as json scan output to a temporary file.
func writeScan(t *testing.T, results []Result) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteResults(&buf, results, "json"); err != nil {
		t.Fatal(err)
	}
	return writeFile(t, buf.String())
}

// writeFile writes data to a temporary file and returns its path.
func writeFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadScanRoundTrip(t *testing.T) {
	want := sampleResults()
	want[1].TLS.CertSANs = []string{"web.example.com", "www.example.com"}
	want[1].TLS.CertNotBefore = time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC)
	want = append(want, Result{
		Host: netip.MustParseAddr("2001:db8::1"), Port: 3306, Service: "mysql",
		Version: "8.0.36", Banner: "8.0.36", Latency: 20 * time.Millisecond,
	})

	got, err := LoadScan(writeScan(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed results:\n got %+v\nwant %+v", got, want)
	}
}

func TestLoadScanNormalizesLatency(t *testing.T) {
	in := []Result{{Host: netip.MustParseAddr("10.0.0.1"), Port: 22, Latency: 1234567 * time.Nanosecond}}
	got, err := LoadScan(writeScan(t, in))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Latency != 1230*time.Microsecond {
		t.Errorf("latency = %v, want 1.23ms (json keeps 0.01ms precision)", got[0].Latency)
	}
}

func TestLoadScanTolerant(t *testing.T) {
	// Missing optional fields and unknown fields are fine; so is the object
	// form written with -diff.
	path := writeFile(t, `{
  "results": [
    {"host": "10.0.0.1", "port": 22, "extra": {"nested": true}},
    {"host": "10.0.0.1", "port": 443, "tls": {"version": "TLS 1.2", "future_field": 1}}
  ],
  "diff": {"opened_count": 0}
}`)
	got, err := LoadScan(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{
		{Host: netip.MustParseAddr("10.0.0.1"), Port: 22},
		{Host: netip.MustParseAddr("10.0.0.1"), Port: 443, TLS: &TLSInfo{Version: "TLS 1.2"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	if got, err := LoadScan(writeFile(t, "[]\n")); err != nil || len(got) != 0 {
		t.Errorf("empty scan: got %v, %v, want no results and no error", got, err)
	}
}

func TestLoadScanErrors(t *testing.T) {
	tests := []struct {
		name, data, want string
	}{
		{"empty", "", "file is empty"},
		{"truncated", `[{"host": "10.0.0.1", "port": 22`, "unexpected end of JSON input"},
		{"not json", "HOST  PORT  SERVICE\n10.0.0.1  22  ssh\n", "expected a json array or object"},
		{"csv", "host,port,service\n", "expected a json array or object"},
		{"no results", `{"hosts": []}`, `no "results" array`},
		{"wrong type", `[{"host": "10.0.0.1", "port": "22"}]`, "cannot unmarshal"},
		{"bad host", `[{"host": "not-an-ip", "port": 22}]`, `invalid host "not-an-ip"`},
		{"missing host", `[{"port": 22}]`, `invalid host ""`},
		{"bad port", `[{"host": "10.0.0.1", "port": 0}]`, "invalid port 0"},
	}
	for _, tt := range tests {
		path := writeFile(t, tt.data)
		_, err := LoadScan(path)
		if err == nil {
			t.Errorf("%s: LoadScan succeeded, want an error", tt.name)
			continue
		}
		if !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: error %q should mention %q and the file path", tt.name, err, tt.want)
		}
	}

	if _, err := LoadScan(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Errorf("missing file: error = %v, want a not-exist error", err)
	}
}

func TestDiffScans(t *testing.T) {
	h1, h2 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	tls12 := &TLSInfo{Version: "TLS 1.2", Cipher: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CertSubject: "old.example.com"}
	tls13 := &TLSInfo{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", CertSubject: "old.example.com"}
	old := []Result{
		{Host: h1, Port: 22, Service: "ssh", Version: "OpenSSH_9.6p1", Banner: "SSH-2.0-OpenSSH_9.6p1"},
		{Host: h1, Port: 21, Service: "ftp", Version: "vsFTPd 3.0.3", Banner: "220 (vsFTPd 3.0.3)"},
		{Host: h1, Port: 443, Service: "https", Banner: "HTTP/1.1 200 OK", TLS: tls12},
		{Host: h2, Port: 80, Service: "http", Banner: "HTTP/1.1 200 OK", Latency: time.Millisecond},
		{Host: h2, Port: 8443, Service: "https", TLS: tls12},
	}
	new := []Result{
		{Host: h2, Port: 80, Service: "http", Banner: "HTTP/1.1 200 OK", Latency: 9 * time.Millisecond},
		{Host: h2, Port: 6379, Service: "redis", Banner: "-NOAUTH Authentication required."},
		{Host: h1, Port: 22, Service: "ssh", Version: "OpenSSH_9.7p1", Banner: "SSH-2.0-OpenSSH_9.7p1"},
		{Host: h1, Port: 443, Service: "https", Banner: "HTTP/1.1 200 OK", TLS: tls13},
		{Host: h1, Port: 3000, Service: "http"},
		{Host: h2, Port: 8443, Service: "http", Banner: "HTTP/1.0 400 Bad Request"},
	}
	d := DiffScans(old, new)

	if d.OpenedCount != 2 || d.ClosedCount != 1 || d.ChangedCount != 3 || d.UnchangedCount != 1 {
		t.Errorf("counts = %d opened, %d closed, %d changed, %d unchanged, want 2, 1, 3, 1",
			d.OpenedCount, d.ClosedCount, d.ChangedCount, d.UnchangedCount)
	}
	keys := func(rs []Result) []string {
		var out []string
		for _, r := range rs {
			out = append(out, netip.AddrPortFrom(r.Host, uint16(r.Port)).String())
		}
		return out
	}
	if got := keys(d.Opened); !reflect.DeepEqual(got, []string{"10.0.0.1:3000", "10.0.0.2:6379"}) {
		t.Errorf("opened = %v", got)
	}
	if got := keys(d.Closed); !reflect.DeepEqual(got, []string{"10.0.0.1:21"}) {
		t.Errorf("closed = %v", got)
	}

	want := []PortChange{
		{h1, 22, "ssh", []FieldChange{
			{"version", "OpenSSH_9.6p1", "OpenSSH_9.7p1"},
			{"banner", "SSH-2.0-OpenSSH_9.6p1", "SSH-2.0-OpenSSH_9.7p1"},
		}},
		{h1, 443, "https", []FieldChange{
			{"tls_version", "TLS 1.2", "TLS 1.3"},
			{"tls_cipher", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"},
		}},
		{h2, 8443, "http", []FieldChange{
			{"service", "https", "http"},
			{"banner", "", "HTTP/1.0 400 Bad Request"},
			{"tls_version", "TLS 1.2", ""},
			{"tls_cipher", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ""},
			{"tls_cert_subject", "old.example.com", ""},
		}},
	}
	if !reflect.DeepEqual(d.Changed, want) {
		t.Errorf("changed =\n%+v\nwant\n%+v", d.Changed, want)
	}
}

func TestDiffScansIdentical(t *testing.T) {
	d := DiffScans(sampleResults(), sampleResults())
	if d.OpenedCount+d.ClosedCount+d.ChangedCount != 0 || d.UnchangedCount != 2 {
		t.Errorf("identical scans: %+v", d)
	}
	var buf bytes.Buffer
	if err := WriteDiffSummary(&buf, d, "last.json"); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "No changes since last.json (2 port(s) unchanged).\n" {
		t.Errorf("summary = %q", got)
	}
}

func TestDiffJSON(t *testing.T) {
	old := sampleResults()[:1]
	new := sampleResults()
	new[0].Version = "OpenSSH_9.7"
	d := DiffScans(old, new)

	var buf bytes.Buffer
	if err := WriteResultsMeta(&buf, new, "json", ScanMeta{Diff: &d}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Results []Result `json:"results"`
		Diff    struct {
			OpenedCount  int `json:"opened_count"`
			ChangedCount int `json:"changed_count"`
			Opened       []struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			} `json:"opened"`
			Closed  []any `json:"closed"`
			Changed []struct {
				Host    string        `json:"host"`
				Port    int           `json:"port"`
				Changes []FieldChange `json:"changes"`
			} `json:"changed"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	if len(got.Results) != 2 || got.Diff.OpenedCount != 1 || got.Diff.ChangedCount != 1 {
		t.Errorf("json report = %+v", got)
	}
	if o := got.Diff.Opened; len(o) != 1 || o[0].Host != "10.0.0.1" || o[0].Port != 443 {
		t.Errorf("opened = %+v", o)
	}
	if got.Diff.Closed == nil {
		t.Error(`"closed" should be an empty array, not null`)
	}
	if c := got.Diff.Changed; len(c) != 1 || c[0].Port != 22 ||
		!reflect.DeepEqual(c[0].Changes, []FieldChange{{"version", "OpenSSH_9.6", "OpenSSH_9.7"}}) {
		t.Errorf("changed = %+v", c)
	}

	// The object form loads back as the same results.
	loaded, err := LoadScan(writeFile(t, buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, new) {
		t.Errorf("loaded %+v, want %+v", loaded, new)
	}
}

func TestInScope(t *testing.T) {
	h1, h2 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	results := []Result{{Host: h1, Port: 22}, {Host: h1, Port: 80}, {Host: h2, Port: 22}}
	got := InScope(results, []netip.Addr{h1}, []int{22, 443})
	if !reflect.DeepEqual(got, []Result{{Host: h1, Port: 22}}) {
		t.Errorf("InScope = %+v", got)
	}
}

func TestWriteDiffSummary(t *testing.T) {
	h := netip.MustParseAddr("10.0.0.1")
	d := DiffScans(
		[]Result{
			{Host: h, Port: 21, Service: "ftp", Version: "vsFTPd 3.0.3", Banner: "220 (vsFTPd 3.0.3)"},
			{Host: h, Port: 22, Service: "ssh", Version: "OpenSSH_9.6p1"},
		},
		[]Result{
			{Host: h, Port: 22, Service: "ssh", Version: "OpenSSH_9.7p1"},
			{Host: h, Port: 6379, Service: "redis", Banner: "-NOAUTH Authentication required."},
		},
	)
	var buf bytes.Buffer
	if err := WriteDiffSummary(&buf, d, "scan.json"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Changes since scan.json: 1 opened, 1 closed, 1 changed, 0 unchanged\n",
		"  + opened  10.0.0.1:6379  redis               -NOAUTH Authentication required.\n",
		"  - closed  10.0.0.1:21    ftp (vsFTPd 3.0.3)  220 (vsFTPd 3.0.3)\n",
		"  ~ changed 10.0.0.1:22    ssh\n",
		`      version: "OpenSSH_9.6p1" -> "OpenSSH_9.7p1"` + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary is missing %q:\n%s", want, out)
		}
	}
}

// listenSSH starts a loopback listener that greets clients with an SSH
// banner and returns its port.
func listenSSH(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("SSH-2.0-OpenSSH_9.7p1 Debian-1\r\n"))
			conn.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestRunDiff(t *testing.T) {
	_, port := listenSSH(t)
	gone, closed := listenSSH(t) // open in the previous scan only
	gone.Close()
	h := netip.MustParseAddr("127.0.0.1")
	prev := writeScan(t, []Result{
		{Host: h, Port: port, Service: "ssh", Version: "OpenSSH_9.6p1 Debian-1", Banner: "SSH-2.0-OpenSSH_9.6p1 Debian-1"},
		{Host: h, Port: closed, Service: "ssh"},
		{Host: h, Port: 1, Service: "tcpmux"}, // not scanned this time
	})

	ports := strconv.Itoa(port) + "," + strconv.Itoa(closed)
	t.Run("table", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"-t", "127.0.0.1", "-p", ports, "-q", "-diff", prev}, &stdout, &stderr); code != exitOK {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "ssh (OpenSSH_9.7p1 Debian-1)") {
			t.Errorf("table is missing the version:\n%s", out)
		}
		if !strings.Contains(out, "\nChanges since "+prev+": 0 opened, 1 closed, 1 changed, 0 unchanged\n") {
			t.Errorf("diff summary missing or wrong (port 1 is out of scope):\n%s", out)
		}
	})
	t.Run("json", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"-t", "127.0.0.1", "-p", ports, "-f", "json", "-diff", prev}, &stdout, &stderr); code != exitOK {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		var report struct {
			Results []Result   `json:"results"`
			Diff    DiffReport `json:"diff"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("stdout is not a json report: %v\n%s", err, stdout.String())
		}
		if len(report.Results) != 1 || report.Diff.ClosedCount != 1 || report.Diff.ChangedCount != 1 {
			t.Errorf("report = %+v", report)
		}
		if !strings.Contains(stderr.String(), "Changes since") {
			t.Errorf("json to stdout should put the summary on stderr:\n%s", stderr.String())
		}
	})
}

func TestRunDiffUnreadable(t *testing.T) {
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "nope.json"),
		"corrupt": writeFile(t, "{not json"),
	} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"-t", "127.0.0.1", "-p", "1", "-diff", path}, &stdout, &stderr)
		if code != exitError {
			t.Errorf("%s: exit %d, want %d", name, code, exitError)
		}
		if msg := stderr.String(); !strings.Contains(msg, "could not read previous scan") || !strings.Contains(msg, path) {
			t.Errorf("%s: stderr = %q", name, msg)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: scan ran despite the bad -diff file:\n%s", name, stdout.String())
		}
	}
}

func TestRunDiffOverwriteGuard(t *testing.T) {
	prev := writeScan(t, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-t", "127.0.0.1", "-p", "1", "-diff", prev, "-o", prev}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "add -f json") {
		t.Errorf("exit %d, stderr %q; want a usage error for table output over the -diff file", code, stderr.String())
	}
	if _, err := LoadScan(prev); err != nil {
		t.Errorf("-diff file was damaged: %v", err)
	}
}
