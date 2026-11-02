// Package intel integrates vulnerability intelligence sources (OSV, GHSA, NVD,
// CISA KEV, EPSS) and applies a strict confidence-tier model. The central rule:
// a version or package match establishes APPLICABILITY, never exploitability.
// KEV and EPSS are prioritization signals only. No intelligence source alone
// can produce a CONFIRMED finding.
package intel

import (
	"time"
)

// Tier separates three claims that must never be collapsed.
type Tier int

const (
	TierVersionOnly   Tier = 0 // package/version matches an advisory range
	TierReachable     Tier = 1 // + a reachable call path to the vulnerable symbol
	TierThreatEnriched Tier = 2 // + KEV/EPSS prioritization context
	TierDynamic       Tier = 3 // + a controlled dynamic demonstration
)

// Advisory is a normalized vulnerability record from any source.
type Advisory struct {
	ID           string    // OSV/GHSA/CVE ID
	Aliases      []string  // CVE/GHSA aliases
	Ecosystem    string    // OSV ecosystem, e.g. "Go", "npm", "PyPI"
	Package      string    // package name or purl
	Introduced   string    // range event
	Fixed        string    // fixed version, if known
	LastAffected string
	Severity     string
	CWEs         []string
	Summary      string
	References   []string
	Modified     time.Time
	Source       string // "osv", "ghsa", "nvd"
}

// ThreatContext carries prioritization signals that are NOT exploitability.
type ThreatContext struct {
	InKEV        bool    // CISA Known Exploited Vulnerabilities membership
	EPSS         float64 // 30-day exploitation probability [0,1]
	EPSSPercentile float64
	EPSSModel    string // EPSS model version, for reproducibility
	KEVCatalog   string // KEV catalogVersion, for freshness
}

// Assessment combines an advisory match with reachability and threat context
// into an explicit, explainable confidence statement.
type Assessment struct {
	Advisory  Advisory
	Tier      Tier
	Threat    ThreatContext
	Reachable bool
	// Confidence is capped by tier: version-only can never be high.
	Confidence float64
	// Statement is the human-readable, accurate claim.
	Statement string
}

// Assess applies the tier model. It never claims exploitability from a version
// match. KEV/EPSS raise prioritization, not the local exploit probability.
func Assess(a Advisory, reachable bool, threat ThreatContext) Assessment {
	as := Assessment{Advisory: a, Reachable: reachable, Threat: threat}
	switch {
	case reachable && threat.InKEV:
		as.Tier = TierThreatEnriched
		as.Confidence = 0.7
		as.Statement = "affected version is reachable and the CVE is known-exploited in the wild; prioritize for dynamic verification"
	case reachable:
		as.Tier = TierReachable
		as.Confidence = 0.6
		as.Statement = "affected version with a reachable call path; applicability established, exploitability not confirmed"
	case threat.InKEV:
		as.Tier = TierThreatEnriched
		as.Confidence = 0.5
		as.Statement = "affected version present and known-exploited elsewhere; reachability not established"
	default:
		as.Tier = TierVersionOnly
		as.Confidence = 0.35
		as.Statement = "affected version range match only; not evidence of a reachable or exploitable vulnerability"
	}
	return as
}

// NeverConfirmed documents the invariant as code: an Assessment has no path to
// a CONFIRMED status. Dynamic confirmation is a separate, engine-driven step.
func (a Assessment) NeverConfirmed() bool { return true }
