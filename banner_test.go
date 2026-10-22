package main

import "testing"

func TestGuessService(t *testing.T) {
	mysql := append([]byte{0x4a, 0, 0, 0, 0x0a}, []byte("8.0.36\x00\x08\x00\x00\x00abc")...)
	tests := []struct {
		banner string
		port   int
		want   string
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", 2222, "ssh"},
		{"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", 8080, "http"},
		{"HTTP/1.0 400 Bad Request\r\n", 443, "http"},
		{"220 mail.example.com ESMTP Postfix\r\n", 2525, "smtp"},
		{"220 mx.example.com ready\r\n", 25, "smtp"},
		{"220 (vsFTPd 3.0.5)\r\n", 21, "ftp"},
		{"220 ProFTPD Server ready.\r\n", 2121, "ftp"},
		{"+OK Dovecot ready.\r\n", 110, "pop3"},
		{"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", 143, "imap"},
		{"-ERR unknown command ''\r\n", 6379, "redis"},
		{"-NOAUTH Authentication required.\r\n", 7000, "redis"},
		{"RFB 003.008\n", 5901, "vnc"},
		{string(mysql), 3307, "mysql"},
		{"", 3389, "rdp"},
		{"", 443, "https"},
		{"\x00\x01garbage", 45678, "unknown"},
	}
	for _, tt := range tests {
		if got := GuessService([]byte(tt.banner), tt.port); got != tt.want {
			t.Errorf("GuessService(%q, %d) = %q, want %q", tt.banner, tt.port, got, tt.want)
		}
	}
}

func TestCleanBanner(t *testing.T) {
	mysql := append([]byte{0x4a, 0, 0, 0, 0x0a}, []byte("5.7.44-log\x00\x08\x00rest")...)
	tests := []struct {
		raw  []byte
		max  int
		want string
	}{
		{[]byte("SSH-2.0-OpenSSH_9.6\r\n"), 60, "SSH-2.0-OpenSSH_9.6"},
		{[]byte("HTTP/1.1 200 OK\r\nServer: x\r\n"), 60, "HTTP/1.1 200 OK"},
		{[]byte("abcdefghijklmnop"), 10, "abcdefg..."},
		{[]byte("\x00\x01hi\x7f there"), 60, "hi there"},
		{mysql, 60, "5.7.44-log"},
		{nil, 60, ""},
	}
	for _, tt := range tests {
		if got := CleanBanner(tt.raw, tt.max); got != tt.want {
			t.Errorf("CleanBanner(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}
