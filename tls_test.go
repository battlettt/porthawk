package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dial connects to a test server's listener.
func dial(t *testing.T, srv *httptest.Server) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// serverPort returns the TCP port a test server listens on.
func serverPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// asTLSPort makes the scanner treat port as an HTTPS port for the
// duration of the test.
func asTLSPort(t *testing.T, port int) {
	t.Helper()
	tlsPorts[port], webPorts[port] = "https", true
	t.Cleanup(func() {
		delete(tlsPorts, port)
		delete(webPorts, port)
	})
}

// scanOne runs a scan of a single loopback port and returns its result.
func scanOne(t *testing.T, s *Scanner, port int) Result {
	t.Helper()
	var results []Result
	for r := range s.Scan(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, []int{port}) {
		results = append(results, r)
	}
	if len(results) != 1 {
		t.Fatalf("scan of port %d: got %d results, want 1", port, len(results))
	}
	return results[0]
}

// newCert creates a certificate from tmpl, signed by parent and parentKey,
// or self-signed when parent is nil. It returns the certificate and its key.
func newCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *rsa.PrivateKey) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert
}

// newTLSServer starts an HTTPS test server presenting cert.
func newTLSServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestProbeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "porthawk-test")
	}))
	defer srv.Close()

	tc, info, err := ProbeTLS(dial(t, srv), "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeTLS: %v", err)
	}
	if !strings.HasPrefix(info.Version, "TLS 1.") {
		t.Errorf("Version = %q, want TLS 1.x", info.Version)
	}
	if info.Cipher == "" || strings.HasPrefix(info.Cipher, "0x") {
		t.Errorf("Cipher = %q, want a named suite", info.Cipher)
	}
	if info.ServerName != "example.com" {
		t.Errorf("ServerName = %q", info.ServerName)
	}
	// httptest's certificate has no CommonName, only an Organization.
	if info.CertSubject != "Acme Co" || info.CertIssuer != "Acme Co" {
		t.Errorf("subject/issuer = %q/%q, want Acme Co", info.CertSubject, info.CertIssuer)
	}
	if !slices.Contains(info.CertSANs, "example.com") {
		t.Errorf("CertSANs = %v, want example.com", info.CertSANs)
	}
	if info.CertNotBefore.IsZero() || !info.CertNotAfter.After(info.CertNotBefore) {
		t.Errorf("validity = %v to %v", info.CertNotBefore, info.CertNotAfter)
	}
	if info.CertExpired {
		t.Error("CertExpired = true for a valid certificate")
	}
	if !info.CertSelfSigned {
		t.Error("CertSelfSigned = false for httptest's self-signed certificate")
	}
	if info.CertSigAlg == "" {
		t.Error("CertSigAlg is empty")
	}
	if info.CertHostMismatch {
		t.Error("CertHostMismatch = true for a name in the certificate")
	}

	// The returned connection carries the HTTP probe.
	banner := GrabBanner(tc, "example.com", 443, 2*time.Second)
	if got := tlsService(GuessService(banner, 443), 443); got != "https" {
		t.Errorf("service over TLS = %q (banner %q), want https", got, banner)
	}
	if !strings.Contains(string(banner), "Server: porthawk-test") {
		t.Errorf("banner over TLS = %q, want the test server's response", banner)
	}
}

func TestProbeTLSHostMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	_, info, err := ProbeTLS(dial(t, srv), "other.test", 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeTLS: %v", err)
	}
	if !info.CertHostMismatch {
		t.Error("CertHostMismatch = false for a name not in the certificate")
	}
}

func TestProbeTLSPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	if tc, _, err := ProbeTLS(dial(t, srv), "127.0.0.1", 2*time.Second); err == nil || tc != nil {
		t.Errorf("ProbeTLS against plain HTTP: conn %v, err %v; want an error", tc, err)
	}
}

func TestProbeTLSExpiredCert(t *testing.T) {
	notAfter := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	cert, _ := newCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired.test"},
		DNSNames:     []string{"expired.test"},
		NotBefore:    notAfter.Add(-30 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, nil, nil)
	srv := newTLSServer(t, cert)

	_, info, err := ProbeTLS(dial(t, srv), "expired.test", 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeTLS: %v", err)
	}
	if !info.CertExpired {
		t.Error("CertExpired = false for a certificate that expired yesterday")
	}
	if !info.CertNotAfter.Equal(notAfter) {
		t.Errorf("CertNotAfter = %v, want %v", info.CertNotAfter, notAfter)
	}
	if info.CertSubject != "expired.test" || info.CertIssuer != "expired.test" {
		t.Errorf("subject/issuer = %q/%q", info.CertSubject, info.CertIssuer)
	}
	if !info.CertSelfSigned {
		t.Error("CertSelfSigned = false for a self-signed leaf")
	}
	if info.CertSigAlg != "SHA256-RSA" {
		t.Errorf("CertSigAlg = %q, want SHA256-RSA", info.CertSigAlg)
	}
	if got := tlsColumn(&info); got != info.shortVersion()+"!" {
		t.Errorf("table TLS column = %q, want expiry marker", got)
	}
}

func TestProbeTLSCASigned(t *testing.T) {
	now := time.Now()
	caTLS, ca := newCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "porthawk test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, nil)
	leaf, _ := newCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Leaf Org"}},
		DNSNames:     []string{"a.test", "b.test", "c.test", "d.test", "e.test", "f.test", "g.test", "h.test", "i.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caTLS.PrivateKey.(*rsa.PrivateKey))
	srv := newTLSServer(t, leaf)

	_, info, err := ProbeTLS(dial(t, srv), "a.test", 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeTLS: %v", err)
	}
	if info.CertSelfSigned {
		t.Error("CertSelfSigned = true for a CA-signed leaf")
	}
	if info.CertSubject != "Leaf Org" || info.CertIssuer != "porthawk test CA" {
		t.Errorf("subject/issuer = %q/%q", info.CertSubject, info.CertIssuer)
	}
	if len(info.CertSANs) != maxSANs || info.CertSANs[0] != "a.test" {
		t.Errorf("CertSANs = %v, want the first %d names", info.CertSANs, maxSANs)
	}
}

func TestScanTLSPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	port := serverPort(t, srv)
	asTLSPort(t, port)

	r := scanOne(t, &Scanner{Workers: 1, Timeout: 2 * time.Second}, port)
	if r.TLS == nil {
		t.Fatal("TLS = nil for an HTTPS server")
	}
	if r.Service != "https" {
		t.Errorf("Service = %q, want https", r.Service)
	}
	if !strings.HasPrefix(r.Banner, "HTTP/") {
		t.Errorf("Banner = %q, want an HTTP status line read over TLS", r.Banner)
	}

	r = scanOne(t, &Scanner{Workers: 1, Timeout: 2 * time.Second, NoTLS: true}, port)
	if r.TLS != nil {
		t.Errorf("TLS = %+v with NoTLS set, want nil", r.TLS)
	}
}

func TestScanPlainHTTPOnTLSPort(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	port := serverPort(t, srv)
	asTLSPort(t, port)

	r := scanOne(t, &Scanner{Workers: 1, Timeout: 2 * time.Second}, port)
	if r.TLS != nil {
		t.Errorf("TLS = %+v for a plain HTTP server, want nil", r.TLS)
	}
	// After the failed handshake the scanner reconnects and probes in plaintext.
	if r.Service != "http" || !strings.HasPrefix(r.Banner, "HTTP/") {
		t.Errorf("Service %q, Banner %q; want a plaintext HTTP response", r.Service, r.Banner)
	}
}

func TestTLSService(t *testing.T) {
	tests := []struct {
		guess string
		port  int
		want  string
	}{
		{"http", 443, "https"},
		{"http", 8443, "https"},
		{"https-alt", 8443, "https"}, // port-number fallback replaced
		{"imap", 993, "imaps"},
		{"pop3", 995, "pop3s"},
		{"smtp", 465, "smtps"},
		{"unknown", 636, "ldaps"},
		{"ssh", 443, "ssh"}, // strong banner match kept
	}
	for _, tt := range tests {
		if got := tlsService(tt.guess, tt.port); got != tt.want {
			t.Errorf("tlsService(%q, %d) = %q, want %q", tt.guess, tt.port, got, tt.want)
		}
	}
}
