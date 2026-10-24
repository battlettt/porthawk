package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

// webPorts are ports that get an HTTP HEAD probe instead of waiting for
// the server to speak first.
var webPorts = map[int]bool{
	80: true, 81: true, 443: true, 3000: true, 5000: true, 8000: true,
	8008: true, 8080: true, 8081: true, 8443: true, 8888: true, 9000: true,
}

// wellKnown maps ports to a service name, used when no banner matches.
var wellKnown = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
	631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
	3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
	8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

// maxBanner is the most bytes read from a service.
const maxBanner = 512

// GrabBanner reads an identifying banner from an open connection. Web ports
// get an HTTP HEAD request; other ports are first given a chance to speak,
// then nudged with a bare CRLF. It returns the raw bytes received, which
// may be empty if the service stays silent.
func GrabBanner(conn net.Conn, host string, port int, timeout time.Duration) []byte {
	if webPorts[port] {
		req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: porthawk\r\n\r\n", host)
		if _, err := conn.Write([]byte(req)); err != nil {
			return nil
		}
		return readSome(conn, timeout)
	}
	if b := readSome(conn, timeout); len(b) > 0 {
		return b
	}
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		return nil
	}
	return readSome(conn, timeout)
}

// readSome performs a single deadline-bounded read.
func readSome(conn net.Conn, timeout time.Duration) []byte {
	buf := make([]byte, maxBanner)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, _ := conn.Read(buf)
	return buf[:n]
}

// GuessService identifies a service from its banner, falling back to the
// conventional service for the port, or "unknown".
func GuessService(banner []byte, port int) string {
	s := string(banner)
	upper := strings.ToUpper(s)
	switch {
	case strings.HasPrefix(s, "SSH-"):
		return "ssh"
	case strings.HasPrefix(s, "HTTP/"):
		return "http"
	case strings.HasPrefix(s, "220"):
		if strings.Contains(upper, "FTP") {
			return "ftp"
		}
		if strings.Contains(upper, "SMTP") || strings.Contains(upper, "MAIL") || port == 25 || port == 587 {
			return "smtp"
		}
		return "ftp"
	case strings.HasPrefix(s, "+OK"):
		return "pop3"
	case strings.HasPrefix(s, "* OK"), strings.HasPrefix(s, "* PREAUTH"):
		return "imap"
	case strings.HasPrefix(s, "-ERR"), strings.HasPrefix(s, "-NOAUTH"),
		strings.HasPrefix(s, "-DENIED"), strings.HasPrefix(s, "+PONG"):
		return "redis"
	case strings.HasPrefix(s, "RFB "):
		return "vnc"
	case isMySQLGreeting(banner):
		return "mysql"
	}
	if name, ok := wellKnown[port]; ok {
		return name
	}
	return "unknown"
}

// isMySQLGreeting reports whether b looks like a MySQL/MariaDB handshake:
// a 3-byte length, a sequence number of 0, then protocol version 10.
func isMySQLGreeting(b []byte) bool {
	return len(b) > 5 && b[3] == 0 && b[4] == 0x0a
}

// CleanBanner turns raw banner bytes into a single printable line of at
// most max runes, suitable for display. All control characters are
// stripped, including the C1 range U+0080-U+009F, so terminal escape
// sequences smuggled into a banner cannot reformat the output.
func CleanBanner(b []byte, max int) string {
	if isMySQLGreeting(b) {
		// Skip the binary header; the server version is a NUL-terminated string.
		v, _, _ := bytes.Cut(b[5:], []byte{0})
		b = v
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0xfffd {
			return -1
		}
		return r
	}, string(line))
	out = strings.TrimSpace(out)
	if max < 0 {
		max = 0
	}
	if r := []rune(out); len(r) > max {
		if max <= 3 {
			out = string(r[:max])
		} else {
			out = string(r[:max-3]) + "..."
		}
	}
	return out
}
