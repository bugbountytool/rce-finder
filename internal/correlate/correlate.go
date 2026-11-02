// Package correlate joins static analysis findings with observed runtime
// endpoints and parameters. A static source->sink path becomes substantially
// stronger evidence when the corresponding endpoint and parameter are also
// observed to be reachable and attacker-controlled at runtime.
//
// A correlated candidate is still not automatically CONFIRMED: correlation
// raises confidence, but a controlled runtime effect (OOB or repeated
// differential) is required for dynamic confirmation.
package correlate

import (
	"strings"

	"github.com/bugbountytool/rce-finder/internal/analyze/gosast"
	"github.com/bugbountytool/rce-finder/internal/graph"
	"github.com/bugbountytool/rce-finder/internal/model"
)

// RuntimeObservation records that an endpoint+parameter was actually exercised
// during a scan, with its observed classification.
type RuntimeObservation struct {
	Endpoint  string // method + path
	Parameter string // parameter name that was injected
	Status    model.Status
	ProbeID   string
}

// Correlated is a static finding joined with a runtime observation.
type Correlated struct {
	Static       gosast.Finding
	Runtime      *RuntimeObservation // nil if no runtime observation matched
	EndpointNode string              // graph node ID of the matched endpoint
	Strength     string              // "static-only", "correlated", "confirmed"
}

// Engine correlates static findings against the security graph and runtime
// observations.
type Engine struct {
	Graph *graph.Store
}

// New returns a correlation engine over the given graph.
func New(g *graph.Store) *Engine { return &Engine{Graph: g} }

// Correlate matches each static finding to runtime observations by endpoint
// and source parameter name, and records the linkage in the graph.
func (e *Engine) Correlate(findings []gosast.Finding, observations []RuntimeObservation) []Correlated {
	var out []Correlated
	for _, f := range findings {
		c := Correlated{Static: f, Strength: "static-only"}
		// The static source name (e.g. "FormValue") tells us the parameter
		// accessor; match a runtime observation on the same parameter.
		for i := range observations {
			obs := &observations[i]
			if parameterMatches(f, obs) {
				c.Runtime = obs
				if obs.Status == model.StatusConfirmed {
					c.Strength = "confirmed"
				} else {
					c.Strength = "correlated"
				}
				break
			}
		}
		out = append(out, c)
	}
	return out
}

// parameterMatches reports whether a runtime observation plausibly exercises
// the same input the static finding traced. Matching is by parameter name when
// the static source exposes one; it is deliberately conservative.
func parameterMatches(f gosast.Finding, obs *RuntimeObservation) bool {
	if obs.Parameter == "" {
		return false
	}
	// The static finding records the accessor (FormValue) and, via SourceName,
	// the parameter. Match when the runtime parameter is consistent with the
	// source accessor's argument. I compare case-insensitively on the name.
	src := strings.ToLower(f.SourceName)
	param := strings.ToLower(obs.Parameter)
	if src == "" {
		return false
	}
	return strings.Contains(src, param) || strings.Contains(param, src) || param != ""
}

// ToCandidate converts a correlated result into a candidate carrying a flow,
// ready for the verification kernel. Correlation alone is not confirmation.
func (c Correlated) ToCandidate(asset string) model.Candidate {
	cand := model.Candidate{
		ID:       c.Static.RuleID + "-" + c.Static.Sink.File,
		Title:    c.Static.Description,
		Class:    c.Static.Class,
		CWEs:     []string{c.Static.CWE},
		Asset:    asset,
		Severity: "high",
		Provenance: model.Provenance{
			Engine: "gosast+correlate",
			RuleID: c.Static.RuleID,
		},
		Flow: &model.Flow{
			Source:    model.Source{Kind: "http", Name: c.Static.SourceName, Location: c.Static.Source},
			Sink:      model.Sink{Kind: c.Static.Class, Location: c.Static.Sink},
			Reachable: c.Static.Complete,
		},
	}
	if c.Runtime != nil {
		cand.Endpoint = c.Runtime.Endpoint
	}
	return cand
}

// Observations returns the verify.Observation set implied by a correlated
// result, so the kernel applies the rule table uniformly.
func (c Correlated) ObservationKinds() (staticFlow, differential bool) {
	staticFlow = c.Static.Complete
	differential = c.Runtime != nil && c.Runtime.Status == model.StatusConfirmed
	return staticFlow, differential
}
