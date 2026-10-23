package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractService(t *testing.T) {
	mysql := append([]byte{0x4a, 0, 0, 0, 0x0a}, []byte("8.0.36\x00\x08\x00\x00\x00abc")...)
	mariadb := append([]byte{0x5b, 0, 0, 0, 0x0a}, []byte("5.5.5-10.11.6-MariaDB-0+deb12u1\x00rest")...)
	tests := []struct {
		banner      string
		port        int
		wantService string
		wantVersion string
	}{
		// SSH
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", 22, "ssh", "OpenSSH_9.6p1 Ubuntu-3ubuntu13"},
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n", 2222, "ssh", "OpenSSH_9.6p1 Ubuntu"},
		{"SSH-2.0-dropbear_2022.83\r\n", 22, "ssh", "dropbear_2022.83"},
		{"SSH-1.99-Cisco-1.25\n", 22, "ssh", "Cisco-1.25"},
		// HTTP Server headers
		{"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\nServer: nginx/1.24.0\r\n\r\n", 80, "http", "nginx/1.24.0"},
		{"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Debian)\r\nContent-Length: 0\r\n\r\n", 8080, "http", "Apache/2.4.57 (Debian)"},
		{"HTTP/1.1 302 Found\r\nserver: Microsoft-IIS/10.0\r\n\r\n", 80, "http", "Microsoft-IIS/10.0"},
		{"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", 80, "http", ""},
		{"HTTP/1.1 200 OK\r\nX-Server: evil/6.6\r\n\r\n", 80, "http", ""},
		// FTP
		{"220 ProFTPD 1.3.8a Server (Debian) [::ffff:10.0.0.5]\r\n", 21, "ftp", "ProFTPD 1.3.8a"},
		{"220 ProFTPD Server ready.\r\n", 21, "ftp", ""},
		{"220 (vsFTPd 3.0.3)\r\n", 21, "ftp", "vsFTPd 3.0.3"},
		{"220-FileZilla Server 1.8.0\r\n220 Please visit https://filezilla-project.org/\r\n", 21, "ftp", "FileZilla Server 1.8.0"},
		{"220 FileZilla Server version 0.9.60 beta\r\n", 21, "ftp", "FileZilla Server 0.9.60 beta"},
		// SMTP
		{"220 mail.example.com ESMTP Postfix 3.7.4\r\n", 25, "smtp", "Postfix 3.7.4"},
		{"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", 25, "smtp", ""},
		{"220 mx.example.com ESMTP Exim 4.96 Fri, 23 Oct 2026 10:00:00 +0000\r\n", 25, "smtp", "Exim 4.96"},
		{"220 mx.example.com ESMTP Sendmail 8.15.2/8.15.2; Fri, 23 Oct 2026\r\n", 587, "smtp", "Sendmail 8.15.2/8.15.2"},
		{"220 ex01.corp.example Microsoft ESMTP MAIL Service, Version: 10.0.17763.1 ready at Fri\r\n", 25, "smtp", "Microsoft ESMTP 10.0.17763.1"},
		// MySQL greetings reuse the version CleanBanner extracts.
		{string(mysql), 3306, "mysql", "8.0.36"},
		{string(mariadb), 3306, "mysql", "5.5.5-10.11.6-MariaDB-0+deb12u1"},
		// Patterns only apply to the service they belong to.
		{"+OK Dovecot ready.\r\n", 110, "pop3", ""},
		{"RFB 003.008\n", 5900, "vnc", ""},
		{"Server: nginx/1.24.0\r\n", 6379, "redis", ""},
		{"", 22, "ssh", ""},
		{"\x00\x01garbage", 45678, "unknown", ""},
	}
	for _, tt := range tests {
		service, version := ExtractService([]byte(tt.banner), tt.port)
		if service != tt.wantService || version != tt.wantVersion {
			t.Errorf("ExtractService(%q, %d) = %q, %q, want %q, %q",
				tt.banner, tt.port, service, version, tt.wantService, tt.wantVersion)
		}
		if guess := GuessService([]byte(tt.banner), tt.port); guess != service {
			t.Errorf("ExtractService(%q) service %q differs from GuessService %q", tt.banner, service, guess)
		}
	}
}

func TestExtractVersionSanitized(t *testing.T) {
	_, version := ExtractService([]byte("SSH-2.0-Open\x1b[31mSSH_9.6\x00\r\n"), 22)
	if version != "Open[31mSSH_9.6" {
		t.Errorf("version = %q, want control characters stripped", version)
	}
}

func TestScanPopulatesVersion(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
	}))
	t.Cleanup(srv.Close)
	port := serverPort(t, srv)
	asTLSPort(t, port)

	r := scanOne(t, &Scanner{Workers: 1, Timeout: 2 * time.Second}, port)
	if r.Service != "https" || r.Version != "nginx/1.24.0" {
		t.Errorf("service, version = %q, %q, want https, nginx/1.24.0", r.Service, r.Version)
	}
}
