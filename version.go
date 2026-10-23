package main

import (
	"regexp"
	"strings"
)

// versionPattern extracts a software version from banners of one service.
// The capture groups that matched are joined with spaces to form the
// version, so a pattern can keep the product name and drop filler text.
type versionPattern struct {
	service string
	re      *regexp.Regexp
}

// versionPatterns are tried in order against banners whose service matches.
var versionPatterns = []versionPattern{
	// SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13: software version and comment.
	{"ssh", regexp.MustCompile(`^SSH-[\d.]+-([^\r\n]+)`)},
	// Server: nginx/1.24.0, Apache/2.4.57 (Debian), Microsoft-IIS/10.0.
	{"http", regexp.MustCompile(`(?im)^Server:[ \t]*([\w.-]+/[\w.-]+(?:[ \t]+\([^)\r\n]*\))?)`)},
	// 220 ProFTPD 1.3.8a Server (Debian) [::ffff:10.0.0.5]
	{"ftp", regexp.MustCompile(`^220[- ](ProFTPD \d[\w.]*)`)},
	// 220 (vsFTPd 3.0.3)
	{"ftp", regexp.MustCompile(`^220[- ]\((vsFTPd \d[\w.]*)\)`)},
	// 220-FileZilla Server 1.8.0, 220 FileZilla Server version 0.9.60 beta
	{"ftp", regexp.MustCompile(`^220[- ](FileZilla Server) (?:version )?(\d[\w.]*(?: beta)?)`)},
	// 220 mail.example.com ESMTP Postfix 3.7.4, ... ESMTP Exim 4.96 ...,
	// ... ESMTP Sendmail 8.15.2/8.15.2; ...
	{"smtp", regexp.MustCompile(`^220[- ]\S+ E?SMTP ((?:Postfix|Exim|Sendmail) \d[\w.]*(?:/[\w.]+)?)`)},
	// 220 mx.example.com Microsoft ESMTP MAIL Service, Version: 10.0.17763.1 ready
	{"smtp", regexp.MustCompile(`^220[- ]\S+ (Microsoft ESMTP) MAIL Service, Version: (\d[\d.]*)`)},
}

// ExtractService identifies a service from its banner like GuessService,
// and also extracts the server software version when the banner carries a
// recognized one. The version is "" when unknown.
func ExtractService(banner []byte, port int) (service, version string) {
	service = GuessService(banner, port)
	return service, extractVersion(banner, service)
}

// extractVersion returns the software version in banner, which GuessService
// identified as service, or "" if no pattern matches.
func extractVersion(banner []byte, service string) string {
	if service == "mysql" && isMySQLGreeting(banner) {
		return CleanBanner(banner, bannerLen)
	}
	for _, p := range versionPatterns {
		if p.service != service {
			continue
		}
		m := p.re.FindSubmatch(banner)
		if m == nil {
			continue
		}
		var parts []string
		for _, g := range m[1:] {
			if len(g) > 0 {
				parts = append(parts, string(g))
			}
		}
		return CleanBanner([]byte(strings.Join(parts, " ")), bannerLen)
	}
	return ""
}
