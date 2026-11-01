package requestctx

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// explicitCookieJar supplies the operator's cookies only to the explicitly
// supplied targets. It does not persist cookies or accept server-set cookies.
type explicitCookieJar struct {
	cookies []*http.Cookie
	hosts   map[string]bool
}

func (j explicitCookieJar) Cookies(u *url.URL) []*http.Cookie {
	if u.Scheme != "https" || !j.hosts[u.Host] {
		return nil
	}
	out := make([]*http.Cookie, len(j.cookies))
	copy(out, j.cookies)
	return out
}
func (j explicitCookieJar) SetCookies(*url.URL, []*http.Cookie) {}

// Validation failures never include cookie values, and the jar is not a report
// or snapshot field.
func Cookies(entries []string) (http.CookieJar, error) {
	return CookiesForHosts(entries, nil)
}

// CookiesForHosts binds cookies to explicit HTTPS target authorities. An empty
// host list creates an inert jar, preventing accidental credential forwarding.
func CookiesForHosts(entries []string, hosts []string) (http.CookieJar, error) {
	jar := explicitCookieJar{hosts: make(map[string]bool, len(hosts))}
	for _, host := range hosts {
		jar.hosts[host] = true
	}
	var cookies []*http.Cookie
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		if !ok || !httpgutsValidCookieName(name) || strings.ContainsAny(name+value, "\r\n;\x00") || !validCookieValue(value) {
			return nil, fmt.Errorf("invalid -cookie option; use name=value with no newlines, semicolons, or control characters (value not shown)")
		}
		cookies = append(cookies, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true})
	}
	jar.cookies = cookies
	return jar, nil
}

func httpgutsValidCookieName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}

func validCookieValue(value string) bool {
	for _, r := range value {
		if r < 0x20 || r >= 0x7f || r == '"' || r == ',' || r == '\\' {
			return false
		}
	}
	return true
}
