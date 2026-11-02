// Package config statically assesses infrastructure and container
// configuration for security weaknesses: Docker/Kubernetes privilege settings,
// secrets exposure, and unsafe management interfaces. All checks are passive
// (static file analysis); none contacts a cluster or cloud API.
package config

import (
	"regexp"
	"strings"
)

// Finding is one configuration weakness.
type Finding struct {
	RuleID   string
	Class    string
	CWE      string
	Severity string
	File     string
	Line     int
	Detail   string
}

// Rule is a declarative configuration check.
type Rule struct {
	ID       string
	Class    string
	CWE      string
	Severity string
	// Pattern matches the offending configuration text.
	Pattern *regexp.Regexp
	// FileMatch restricts the rule to files whose name matches.
	FileMatch *regexp.Regexp
	Detail    string
}

// DefaultRules returns the built-in container/Kubernetes/IaC rules.
func DefaultRules() []Rule {
	return []Rule{
		{ID: "docker-privileged", Class: "container-privilege", CWE: "CWE-250", Severity: "high",
			Pattern: regexp.MustCompile(`(?i)privileged:\s*true`), FileMatch: regexp.MustCompile(`(?i)(docker-compose|\.ya?ml$)`),
			Detail: "container runs in privileged mode, disabling most isolation"},
		{ID: "docker-sock-mount", Class: "container-escape-risk", CWE: "CWE-250", Severity: "high",
			Pattern: regexp.MustCompile(`/var/run/docker\.sock`), FileMatch: regexp.MustCompile(`(?i)(docker-compose|\.ya?ml$)`),
			Detail: "Docker socket is mounted, allowing container escape to the host"},
		{ID: "k8s-allow-priv-escalation", Class: "container-privilege", CWE: "CWE-250", Severity: "high",
			Pattern: regexp.MustCompile(`(?i)allowPrivilegeEscalation:\s*true`), FileMatch: regexp.MustCompile(`(?i)\.ya?ml$`),
			Detail: "pod allows privilege escalation"},
		{ID: "k8s-host-network", Class: "network-exposure", CWE: "CWE-668", Severity: "medium",
			Pattern: regexp.MustCompile(`(?i)hostNetwork:\s*true`), FileMatch: regexp.MustCompile(`(?i)\.ya?ml$`),
			Detail: "pod shares the host network namespace"},
		{ID: "k8s-run-as-root", Class: "container-privilege", CWE: "CWE-250", Severity: "medium",
			Pattern: regexp.MustCompile(`(?i)runAsUser:\s*0\b`), FileMatch: regexp.MustCompile(`(?i)\.ya?ml$`),
			Detail: "container runs as root (UID 0)"},
		{ID: "k8s-seccomp-unconfined", Class: "container-privilege", CWE: "CWE-250", Severity: "high",
			Pattern: regexp.MustCompile(`(?i)seccomp.*[Uu]nconfined`), FileMatch: regexp.MustCompile(`(?i)\.ya?ml$`),
			Detail: "seccomp is unconfined, removing syscall filtering"},
		{ID: "aws-access-key", Class: "secret-exposure", CWE: "CWE-798", Severity: "critical",
			Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), FileMatch: nil,
			Detail: "hardcoded AWS access key ID"},
		{ID: "generic-password", Class: "secret-exposure", CWE: "CWE-798", Severity: "high",
			Pattern: regexp.MustCompile(`(?i)(password|passwd|secret)\s*[:=]\s*["']?[A-Za-z0-9!@#$%^&*]{8,}`), FileMatch: nil,
			Detail: "possible hardcoded credential"},
		{ID: "k8s-latest-tag", Class: "supply-chain", CWE: "CWE-1357", Severity: "low",
			Pattern: regexp.MustCompile(`(?i)image:\s*\S+:(latest|main|master)\b`), FileMatch: regexp.MustCompile(`(?i)\.ya?ml$`),
			Detail: "image uses a mutable tag, undermining reproducibility"},
	}
}

// ScanFile applies all applicable rules to a file's content.
func ScanFile(path string, content []byte) []Finding {
	lines := strings.Split(string(content), "\n")
	rules := DefaultRules()
	var out []Finding
	for _, rule := range rules {
		if rule.FileMatch != nil && !rule.FileMatch.MatchString(path) {
			continue
		}
		for i, line := range lines {
			if rule.Pattern.MatchString(line) {
				out = append(out, Finding{
					RuleID: rule.ID, Class: rule.Class, CWE: rule.CWE,
					Severity: rule.Severity, File: path, Line: i + 1, Detail: rule.Detail,
				})
			}
		}
	}
	return out
}
