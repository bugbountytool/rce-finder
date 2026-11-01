// Package policy defines the non-negotiable safety limits for a scan.
package policy

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Mode determines the maximum kind of template a scan may run.
type Mode string

const (
	ModePassive        Mode = "passive"
	ModeSafeValidation Mode = "safe-validation"
	ModeAdvanced       Mode = "advanced-authorized"
)

// Policy is intentionally deny-by-default. It controls scan behavior but
// never creates targets or expands a supplied scope.
type Policy struct {
	Mode             Mode
	AllowPrivate     bool
	AllowCredentials bool
}

func Default() Policy { return Policy{Mode: ModeSafeValidation} }

func (p Policy) ValidateTarget(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("only absolute HTTP(S) targets are allowed")
	}
	if u.User != nil && !p.AllowCredentials {
		return fmt.Errorf("target URLs with embedded credentials are denied by policy")
	}
	if u.Fragment != "" {
		return fmt.Errorf("target URL fragments are not valid scan targets")
	}
	host := strings.Trim(u.Hostname(), "[]")
	if addr, err := netip.ParseAddr(host); err == nil && !p.AllowPrivate && isNonPublic(addr) {
		return fmt.Errorf("non-public target %q is denied; explicitly enable private targets only for an authorized lab", host)
	}
	return nil
}

func (p Policy) AllowsTemplate(mode Mode) bool {
	return p.Mode == ModeSafeValidation && (mode == "" || mode == ModeSafeValidation)
}

func isNonPublic(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast()
}
