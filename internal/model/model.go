// Package model defines the shared vulnerability data model used by every
// engine: candidates (unverified hypotheses), findings (verified claims),
// evidence references, data-flow paths, and root-cause attribution.
//
// The central design rule: a Candidate is a hypothesis; a Finding is a claim
// that has passed the verification kernel. Only the verify package may set a
// Finding's Status. Status is never inferred from a fingerprint, a version
// string, an error message, or AI text alone.
package model

import (
	"time"

	"github.com/bugbountytool/rce-finder/internal/evidence"
)

// Status is the final classification of a finding. It is intentionally
// conservative: CONFIRMED requires reproducible, attributable evidence.
type Status string

const (
	StatusConfirmed      Status = "CONFIRMED"
	StatusHighConfidence Status = "HIGH_CONFIDENCE"
	StatusPotential      Status = "POTENTIAL"
	StatusInconclusive   Status = "INCONCLUSIVE"
	StatusNotVulnerable  Status = "NOT_VULNERABLE"
	StatusDryRun         Status = "DRY_RUN"
	StatusSkipped        Status = "SKIPPED"
	StatusBlocked        Status = "BLOCKED"
	StatusError          Status = "ERROR"
)

// VerificationBasis records what kind of evidence backs a status, so a
// source-confirmed weakness is never confused with a dynamically confirmed
// exploit. This is reported alongside Status.
type VerificationBasis string

const (
	BasisNone       VerificationBasis = "none"
	BasisDynamic    VerificationBasis = "dynamic"    // observed controlled effect at runtime
	BasisSource     VerificationBasis = "source"     // complete source->sink path, statically
	BasisCorrelated VerificationBasis = "correlated" // static path + observed runtime endpoint
	BasisApplicabil VerificationBasis = "applicability"
)

// Confidence carries a score plus the human-readable reasons for it. The
// score is informational; StatusReason is the authoritative explanation.
type Confidence struct {
	Score   int      `json:"score"`
	Reasons []string `json:"reasons,omitempty"`
}

// Location identifies a precise code position for source-level findings.
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
	Func   string `json:"function,omitempty"`
}

// Source is an entry point for untrusted data.
type Source struct {
	Kind      string   `json:"kind"` // query, body, header, cookie, path, file, message, config
	Name      string   `json:"name,omitempty"`
	Framework string   `json:"framework,omitempty"`
	Location  Location `json:"location"`
}

// Sink is a dangerous operation untrusted data might reach.
type Sink struct {
	Kind      string   `json:"kind"` // exec, eval, template, deserialize, expression, file, classload
	Framework string   `json:"framework,omitempty"`
	Location  Location `json:"location"`
}

// FlowStep is one transformation along a source-to-sink path.
type FlowStep struct {
	Kind     string   `json:"kind"` // parse, decode, concat, render, deserialize, call
	Location Location `json:"location"`
	Detail   string   `json:"detail,omitempty"`
}

// Flow is a complete source-to-sink path with any sanitizers encountered.
type Flow struct {
	Source     Source     `json:"source"`
	Steps      []FlowStep `json:"steps,omitempty"`
	Sink       Sink       `json:"sink"`
	Sanitizers []Location `json:"sanitizers,omitempty"`
	// Reachable records whether a call-graph path to the sink was established.
	Reachable bool `json:"reachable"`
}

// RootCauseClass is the single primary cause of a defect.
type RootCauseClass string

const (
	ControlMissing       RootCauseClass = "control_missing"
	ControlBypassed      RootCauseClass = "control_bypassed"
	ContextMismatch      RootCauseClass = "context_mismatch"
	TypeConfusion        RootCauseClass = "type_confusion"
	AuthzMissing         RootCauseClass = "authz_missing"
	AuthzInconsistent    RootCauseClass = "authz_inconsistent"
	UnsafeDefault        RootCauseClass = "unsafe_default"
	ParserDifferential   RootCauseClass = "parser_differential"
	RaceWindow           RootCauseClass = "race_window"
	UnsafeDeserialization RootCauseClass = "unsafe_deserialization"
	UntrustedConfig      RootCauseClass = "untrusted_config"
	CauseUnknown         RootCauseClass = "unknown"
)

// RootCause explains the defect. Basis distinguishes a source-confirmed cause
// from an inferred one. WeakestLink names the assumption whose falsity would
// invalidate the finding.
type RootCause struct {
	Class       RootCauseClass `json:"class"`
	Basis       string         `json:"basis"` // "source" or "inferred"
	Control     string         `json:"control,omitempty"` // missing/ineffective control
	Explanation string         `json:"explanation,omitempty"`
	WeakestLink string         `json:"weakest_link,omitempty"`
}

// Provenance records which engine produced a finding and the rule that fired,
// so results are reproducible and attributable.
type Provenance struct {
	Engine   string `json:"engine"`
	Version  string `json:"version,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	RuleHash string `json:"rule_hash,omitempty"`
}

// AIAdvisory holds optional model-generated advisory text. It is structurally
// incapable of changing Status: there is no Status field here, and the report
// layer keeps advisory text out of classification fields.
type AIAdvisory struct {
	Advisory    bool   `json:"advisory"` // always true
	Explanation string `json:"explanation,omitempty"`
	CWESuggest  string `json:"cwe_suggestion,omitempty"`
	Remediation string `json:"remediation_draft,omitempty"`
	TriageRank  int    `json:"triage_rank,omitempty"`
	ModelID     string `json:"model_id,omitempty"`
	PromptHash  string `json:"prompt_hash,omitempty"`
	InputDigest string `json:"input_digest,omitempty"`
}

// Finding is a verified claim about an asset. Status is set only by verify.
type Finding struct {
	ID                string           `json:"id"`
	ScanID            string           `json:"scan_id,omitempty"`
	CandidateID       string           `json:"candidate_id,omitempty"`
	Title             string           `json:"title"`
	Class             string           `json:"class"`
	CWEs              []string         `json:"cwe,omitempty"`
	CVEs              []string         `json:"cve,omitempty"`
	Asset             string           `json:"asset"`
	Endpoint          string           `json:"endpoint,omitempty"`
	Severity          string           `json:"severity"`
	Status            Status           `json:"status"`
	StatusReason      string           `json:"status_reason"`
	Basis             VerificationBasis `json:"verification_basis"`
	Confidence        Confidence       `json:"confidence"`
	Flow              *Flow            `json:"flow,omitempty"`
	RootCause         *RootCause       `json:"root_cause,omitempty"`
	Preconditions     []string         `json:"preconditions,omitempty"`
	Impact            string           `json:"impact,omitempty"`
	Remediation       string           `json:"remediation,omitempty"`
	References        []string         `json:"references,omitempty"`
	Evidence          []evidence.Record `json:"evidence,omitempty"`
	Provenance        Provenance       `json:"provenance"`
	AIAdvisory        *AIAdvisory      `json:"ai_advisory,omitempty"`
	ObservedAt        time.Time        `json:"observed_at"`
}

// Candidate is an unverified hypothesis produced by any analyzer. It carries
// no Status; the verification kernel decides whether it becomes a Finding.
type Candidate struct {
	ID            string           `json:"id"`
	Title         string           `json:"title"`
	Class         string           `json:"class"`
	CWEs          []string         `json:"cwe,omitempty"`
	Asset         string           `json:"asset"`
	Endpoint      string           `json:"endpoint,omitempty"`
	Severity      string           `json:"severity"`
	Flow          *Flow            `json:"flow,omitempty"`
	Preconditions []string         `json:"preconditions,omitempty"`
	References    []string         `json:"references,omitempty"`
	Provenance    Provenance       `json:"provenance"`
}
