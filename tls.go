package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strings"
	"time"
)

// tlsPorts are ports that get a TLS handshake before the banner grab, mapped
// to the service name reported when the banner doesn't identify anything
// more specific.
var tlsPorts = map[int]string{
	443: "https", 465: "smtps", 636: "ldaps", 853: "dns-tls", 990: "ftps",
	993: "imaps", 995: "pop3s", 6697: "ircs", 8443: "https",
}

// tlsVariants maps plaintext protocols to their implicit-TLS names, so an
// HTTP banner read over TLS is reported as https.
var tlsVariants = map[string]string{
	"http": "https", "smtp": "smtps", "ftp": "ftps", "imap": "imaps", "pop3": "pop3s",
}

// maxSANs is the most certificate DNS names recorded per result.
const maxSANs = 8

// TLSInfo describes a completed TLS handshake and the server's leaf
// certificate. Certificates are never rejected; problems such as expiry or a
// hostname mismatch are recorded instead.
type TLSInfo struct {
	Version          string    `json:"version"`
	Cipher           string    `json:"cipher"`
	ServerName       string    `json:"server_name,omitempty"`
	CertSubject      string    `json:"cert_subject"`
	CertIssuer       string    `json:"cert_issuer"`
	CertSANs         []string  `json:"cert_sans,omitempty"`
	CertNotBefore    time.Time `json:"cert_not_before"`
	CertNotAfter     time.Time `json:"cert_not_after"`
	CertExpired      bool      `json:"cert_expired"`
	CertSelfSigned   bool      `json:"cert_self_signed"`
	CertSigAlg       string    `json:"cert_sig_alg"`
	CertHostMismatch bool      `json:"cert_host_mismatch"`
}

// ProbeTLS performs a TLS client handshake over conn, bounded by timeout.
// Certificate verification is skipped so that any server can be inspected;
// serverName is sent as SNI (unless it is an IP address) and checked against
// the certificate, with the outcome recorded in CertHostMismatch. On success
// the returned connection can be used to grab a banner. On failure conn is
// left open but unusable for plaintext, and the caller should close it.
func ProbeTLS(conn net.Conn, serverName string, timeout time.Duration) (*tls.Conn, TLSInfo, error) {
	tc := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		// Accept old protocol versions and weak ciphers: a scanner should
		// report them, not refuse to talk to them.
		MinVersion:   tls.VersionTLS10,
		CipherSuites: allCipherSuites(),
	})
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, TLSInfo{}, err
	}
	if err := tc.Handshake(); err != nil {
		return nil, TLSInfo{}, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, TLSInfo{}, err
	}

	state := tc.ConnectionState()
	info := TLSInfo{
		Version:    tls.VersionName(state.Version),
		Cipher:     tls.CipherSuiteName(state.CipherSuite),
		ServerName: serverName,
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		info.CertSubject = pkixName(leaf.Subject)
		info.CertIssuer = pkixName(leaf.Issuer)
		info.CertSANs = leaf.DNSNames[:min(len(leaf.DNSNames), maxSANs)]
		info.CertNotBefore = leaf.NotBefore
		info.CertNotAfter = leaf.NotAfter
		info.CertExpired = time.Now().After(leaf.NotAfter)
		info.CertSelfSigned = isSelfSigned(leaf)
		info.CertSigAlg = leaf.SignatureAlgorithm.String()
		info.CertHostMismatch = serverName != "" && leaf.VerifyHostname(serverName) != nil
	}
	return tc, info, nil
}

// allCipherSuites returns the IDs of every cipher suite crypto/tls
// implements, including those it considers insecure.
func allCipherSuites() []uint16 {
	var ids []uint16
	for _, cs := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		ids = append(ids, cs.ID)
	}
	return ids
}

// pkixName returns a short display name: the CommonName, or failing that the
// first Organization.
func pkixName(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	if len(n.Organization) > 0 {
		return n.Organization[0]
	}
	return ""
}

// isSelfSigned reports whether c is signed by its own key. Signatures using
// algorithms crypto/x509 refuses to verify (such as SHA-1) count as
// self-signed when the issuer and subject match.
func isSelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	var insecure x509.InsecureAlgorithmError
	return err == nil || errors.As(err, &insecure)
}

// tlsService picks the service name for a port that completed a TLS
// handshake, given the name GuessService chose from the decrypted banner.
// Plaintext protocols become their TLS variants (http -> https); a name that
// only came from the port number is replaced by the port's TLS service; any
// other banner match (ssh behind a multiplexer, say) is kept.
func tlsService(guess string, port int) string {
	if v, ok := tlsVariants[guess]; ok {
		return v
	}
	if name, ok := tlsPorts[port]; ok && guess == GuessService(nil, port) {
		return name
	}
	return guess
}

// shortVersion returns the protocol version without its "TLS " prefix,
// e.g. "1.3".
func (i *TLSInfo) shortVersion() string {
	return strings.TrimPrefix(i.Version, "TLS ")
}
