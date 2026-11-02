// Package scope enforces explicit target authorization.
//
// Design principle: this tool never discovers or expands its own target
// list. Every target scanned must appear, verbatim, in a file the operator
// supplies. This is a deliberate safety boundary, not an implementation
// detail — it keeps the tool from ever being usable as a mass/opportunistic
// scanner. See docs/USAGE.md and SECURITY.md for the authorization policy
// this enforces.
package scope

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	pathpkg "path"
	"strings"

	"github.com/bugbountytool/rce-finder/internal/policy"
)

// Target is a single in-scope URL the operator has explicitly authorized
// for testing.
type Target struct {
	Raw string
	URL *url.URL
}

// Load reads a target list file: one URL per line, blank lines and lines
// starting with '#' are ignored. It is the ONLY way targets enter the tool.
// There is intentionally no crawler, no subdomain brute-forcer, and no
// "scan this whole CIDR" mode — scope must be enumerated by a human who is
// responsible for having authorization for every line.
func Load(path string) ([]Target, error) {
	return LoadWithPolicy(path, policy.Default())
}

// LoadWithPolicy loads explicit targets and applies the caller's safety
// policy. It never resolves hostnames or performs network I/O.
func LoadWithPolicy(path string, scanPolicy policy.Policy) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening target file: %w", err)
	}
	defer f.Close()

	var targets []Target
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := Parse(line, scanPolicy)
		if err != nil {
			return nil, fmt.Errorf("target file %s line %d: %w", path, lineNo, err)
		}
		targets = append(targets, Target{Raw: line, URL: u})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading target file: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("target file %s contains no valid targets; refusing to run with an empty scope", path)
	}
	return targets, nil
}

// Parse validates one explicit target without resolving its hostname or
// contacting it.
func Parse(raw string, scanPolicy policy.Policy) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid URL %q (must include scheme, e.g. https://)", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if err := scanPolicy.ValidateTarget(u); err != nil {
		return nil, err
	}
	return u, nil
}

// ContainsEndpoint reports whether u falls within an explicitly declared
// target. Scheme, hostname, effective port, and the target's path boundary must
// match. It never resolves hostnames, follows redirects, or reads other URLs.
func ContainsEndpoint(target *url.URL, u *url.URL) bool {
	if target == nil || u == nil || u.User != nil || u.Fragment != "" ||
		!strings.EqualFold(target.Scheme, u.Scheme) ||
		!strings.EqualFold(target.Hostname(), u.Hostname()) ||
		effectivePort(target) != effectivePort(u) {
		return false
	}
	base, err := url.PathUnescape(target.EscapedPath())
	if err != nil {
		return false
	}
	path, err := url.PathUnescape(u.EscapedPath())
	if err != nil {
		return false
	}
	if base == "" {
		base = "/"
	}
	if path == "" {
		path = "/"
	}
	base = strings.TrimSuffix(pathpkg.Clean("/"+strings.TrimPrefix(base, "/")), "/")
	path = pathpkg.Clean("/" + strings.TrimPrefix(path, "/"))
	if base == "" || base == "." {
		return true
	}
	return path == base || strings.HasPrefix(path, base+"/")
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
