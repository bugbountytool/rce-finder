package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

// WriteSARIF emits SARIF 2.1.0 for CI systems and code-scanning consumers.
// It exports scan evidence only; it does not contain request bodies or secrets.
func WriteSARIF(w io.Writer, results []engine.Result) error {
	type driver struct {
		Name  string `json:"name"`
		Rules []rule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type location struct {
		URI string `json:"uri"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             message           `json:"message"`
		Locations           []location        `json:"locations,omitempty"`
		Properties          properties        `json:"properties"`
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	}
	type run struct {
		Tool    tool     `json:"tool"`
		Results []result `json:"results"`
	}
	type document struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []run  `json:"runs"`
	}

	rules := make(map[string]rule)
	var output []result
	for _, item := range results {
		item = sanitized(item)
		if item.Status == engine.StatusDryRun || item.Status == engine.StatusSkipped {
			continue
		}
		id := item.TemplateID
		if id == "" {
			id = "rce-finder"
		}
		rules[id] = rule{ID: id, Name: item.Name, ShortDescription: message{Text: item.Name}, HelpURI: firstReference(item.References)}
		output = append(output, result{
			RuleID: id, Level: sarifLevel(item), Message: message{Text: fmt.Sprintf("%s: %s", item.Classification, item.Detail)},
			Locations:           []location{{URI: item.Target}},
			Properties:          properties{Status: string(item.Status), Classification: string(item.Classification), Severity: item.Severity, ProbeID: item.ProbeID, ScanID: item.ScanID, Evidence: evidenceDigests(item), Confidence: item.Confidence.Score, Remediation: item.Remediation},
			PartialFingerprints: map[string]string{"rceFinderJobId": item.JobID},
		})
	}
	allRules := make([]rule, 0, len(rules))
	for _, value := range rules {
		allRules = append(allRules, value)
	}
	doc := document{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []run{{Tool: tool{Driver: driver{Name: "RCE Finder", Rules: allRules}}, Results: output}}}
	return json.NewEncoder(w).Encode(doc)
}

type message struct {
	Text string `json:"text"`
}
type rule struct {
	ID               string  `json:"id"`
	Name             string  `json:"name,omitempty"`
	ShortDescription message `json:"shortDescription,omitempty"`
	HelpURI          string  `json:"helpUri,omitempty"`
}
type properties struct {
	Status         string   `json:"status"`
	Classification string   `json:"classification,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	ProbeID        string   `json:"probe_id,omitempty"`
	ScanID         string   `json:"scan_id,omitempty"`
	Evidence       []string `json:"evidence_digests,omitempty"`
	Confidence     int      `json:"confidence_score"`
	Remediation    string   `json:"remediation,omitempty"`
}

func evidenceDigests(result engine.Result) []string {
	out := make([]string, 0, len(result.Evidence))
	for _, item := range result.Evidence {
		out = append(out, string(item.Kind)+":"+item.Digest)
	}
	return out
}

func firstReference(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0]
}
func sarifLevel(r engine.Result) string {
	if r.Status == engine.StatusConfirmed {
		return "error"
	}
	if r.Status == engine.StatusError || r.Status == engine.StatusBlocked {
		return "warning"
	}
	return "note"
}
