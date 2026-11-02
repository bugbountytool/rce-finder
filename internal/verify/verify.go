// Package verify is the verification kernel: the only component permitted to
// assign a Finding's Status. It implements an explicit, auditable rule table
// mapping evidence to classifications, and it rejects forbidden transitions
// (e.g. a version match or AI advisory can never produce CONFIRMED).
//
// Design rule: analyzers produce Candidates and Observations; only Verify
// turns them into Findings. This keeps the trust boundary in one place.
package verify

import (
	"fmt"

	"github.com/bugbountytool/rce-finder/internal/evidence"
	"github.com/bugbountytool/rce-finder/internal/model"
)

// Observation is a piece of evidence an engine collected about a candidate.
// The Kind determines how much weight it carries in the rule table.
type Observation struct {
	Kind            ObservationKind
	ProtocolMatches bool // for OOB: callback protocol matched the template
	ProbeIDMatches  bool // for OOB: callback probe ID matched exactly
	Repeated        bool // for differential: reproduced across >=3 controlled trials
	ControlMatched  bool // for differential: control request behaved as expected
	CompleteFlow    bool // for static: a full source->sink path was established
	Reachable       bool // for static: sink is reachable from an exposed entry point
	Note            string
}

type ObservationKind string

const (
	ObsOOBCorrelated ObservationKind = "oob_correlated"   // exact probe-ID + protocol callback
	ObsDifferential  ObservationKind = "differential"     // control-vs-payload behavioral difference
	ObsErrorSig      ObservationKind = "error_signature"  // error/regex match only
	ObsStaticFlow    ObservationKind = "static_flow"      // source->sink dataflow
	ObsStaticPattern ObservationKind = "static_pattern"   // pattern match only
	ObsVersionMatch  ObservationKind = "version_match"    // CPE/OSV range match
	ObsThreatIntel   ObservationKind = "threat_intel"     // KEV/EPSS signal
	ObsFingerprint   ObservationKind = "fingerprint"      // technology identification
	ObsAIAdvisory    ObservationKind = "ai_advisory"      // model-generated text
	ObsNegative      ObservationKind = "negative"         // completed test, no effect observed
	ObsBlocked       ObservationKind = "blocked"          // policy/scope blocked
	ObsError         ObservationKind = "error"            // operational error
)

// Kernel applies the evidence rule table. It is stateless and deterministic.
type Kernel struct{}

func New() *Kernel { return &Kernel{} }

// Verify classifies a candidate from its observations. It returns a Finding
// whose Status is decided solely by the rule table below. The second return
// value is false when the observations are insufficient to classify at all.
func (k *Kernel) Verify(c model.Candidate, obs []Observation) (model.Finding, error) {
	f := model.Finding{
		ID:            c.ID,
		CandidateID:   c.ID,
		Title:         c.Title,
		Class:         c.Class,
		CWEs:          c.CWEs,
		Asset:         c.Asset,
		Endpoint:      c.Endpoint,
		Severity:      c.Severity,
		Flow:          c.Flow,
		Preconditions: c.Preconditions,
		References:    c.References,
		Provenance:    c.Provenance,
		ObservedAt:    nowUTC(),
	}
	status, basis, reason, score := classify(obs)
	f.Status = status
	f.Basis = basis
	f.StatusReason = reason
	f.Confidence = model.Confidence{Score: score, Reasons: []string{reason}}
	f.Evidence = evidenceFor(obs, c.ID)
	if f.Status == "" {
		return f, fmt.Errorf("candidate %s: insufficient evidence to classify", c.ID)
	}
	return f, nil
}

// classify is the evidence rule table. Order matters: the strongest applicable
// rule wins. None of these rules can be reached by a version match, a threat
// intel signal, a fingerprint, or AI text alone.
func classify(obs []Observation) (model.Status, model.VerificationBasis, string, int) {
	var has struct {
		oob, diff, errSig, staticFlow, staticPattern, version, threat, fp, ai, negative, blocked, errObs bool
	}
	var oobExact, diffStrong, staticComplete bool
	for _, o := range obs {
		switch o.Kind {
		case ObsOOBCorrelated:
			has.oob = true
			if o.ProtocolMatches && o.ProbeIDMatches {
				oobExact = true
			}
		case ObsDifferential:
			has.diff = true
			if o.Repeated && o.ControlMatched {
				diffStrong = true
			}
		case ObsErrorSig:
			has.errSig = true
		case ObsStaticFlow:
			has.staticFlow = true
			if o.CompleteFlow && o.Reachable {
				staticComplete = true
			}
		case ObsStaticPattern:
			has.staticPattern = true
		case ObsVersionMatch:
			has.version = true
		case ObsThreatIntel:
			has.threat = true
		case ObsFingerprint:
			has.fp = true
		case ObsAIAdvisory:
			has.ai = true
		case ObsNegative:
			has.negative = true
		case ObsBlocked:
			has.blocked = true
		case ObsError:
			has.errObs = true
		}
	}

	switch {
	case oobExact:
		return model.StatusConfirmed, model.BasisDynamic,
			"exact OOB callback matched both probe ID and protocol", 100
	case diffStrong && staticComplete:
		return model.StatusConfirmed, model.BasisCorrelated,
			"reproducible differential effect plus complete reachable source-to-sink path", 100
	case diffStrong:
		return model.StatusHighConfidence, model.BasisDynamic,
			"controlled differential effect reproduced across >=3 trials with matched control; not OOB-confirmed", 85
	case staticComplete:
		return model.StatusHighConfidence, model.BasisSource,
			"complete reachable source-to-sink path; statically established, not dynamically confirmed", 80
	case has.errSig || has.staticPattern || has.diff || has.staticFlow:
		return model.StatusPotential, model.BasisNone,
			"weak or unrepeated signal only; manual verification required", 40
	case has.blocked:
		return model.StatusBlocked, model.BasisNone,
			"blocked by scope or policy", 0
	case has.errObs:
		return model.StatusError, model.BasisNone,
			"operational error during verification", 0
	case has.negative:
		return model.StatusNotVulnerable, model.BasisNone,
			"completed test observed no effect; not proof of absence", 70
	case has.version || has.threat || has.fp:
		return model.StatusInconclusive, model.BasisApplicabil,
			"applicability or prioritization signal only; never a vulnerability confirmation", 20
	case has.ai:
		return model.StatusInconclusive, model.BasisNone,
			"AI advisory text is not evidence; requires independent verification", 10
	default:
		return "", model.BasisNone, "", 0
	}
}

// evidenceFor converts observations into redacted evidence records.
func evidenceFor(obs []Observation, probeID string) []evidence.Record {
	var out []evidence.Record
	for _, o := range obs {
		attrs := map[string]string{"kind": string(o.Kind)}
		if o.Note != "" {
			attrs["note"] = o.Note
		}
		out = append(out, evidence.New(evidence.Kind("observation"), probeID, nowUTC(), attrs))
	}
	return out
}
