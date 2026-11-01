package planner

import (
	"fmt"
	"strings"

	"github.com/bugbountytool/rce-finder/internal/template"
)

// Decision explains every selected or skipped template. Skipping technology
// applicability is opt-in and never a statement that a target is safe.
type Decision struct {
	TemplateID string   `json:"template_id"`
	Selected   bool     `json:"selected"`
	Reason     string   `json:"reason"`
	Required   []string `json:"required_technologies,omitempty"`
}

type TechnologyEvidence struct {
	Name       string
	Confidence int
	Explicit   bool
}

func Select(templates []*template.Template, evidence []TechnologyEvidence, autoSelect bool) ([]*template.Template, []Decision) {
	if !autoSelect {
		decisions := make([]Decision, 0, len(templates))
		for _, tmpl := range templates {
			decisions = append(decisions, Decision{TemplateID: tmpl.ID, Selected: true, Reason: "explicitly selected; automatic technology filtering disabled"})
		}
		return templates, decisions
	}
	observed := make(map[string]TechnologyEvidence)
	for _, item := range evidence {
		item.Name = strings.ToLower(strings.TrimSpace(item.Name))
		if item.Name != "" {
			observed[item.Name] = item
		}
	}
	var selected []*template.Template
	var decisions []Decision
	for _, tmpl := range templates {
		required := tmpl.Prerequisites.RequiredTechnologies
		if len(required) == 0 {
			required = tmpl.Technologies
		}
		if len(required) == 0 {
			selected = append(selected, tmpl)
			decisions = append(decisions, Decision{TemplateID: tmpl.ID, Selected: true, Reason: "template has no technology prerequisite"})
			continue
		}
		var missing []string
		lowestConfidence := 100
		for _, technology := range required {
			item, ok := observed[strings.ToLower(technology)]
			if !ok {
				missing = append(missing, technology)
				continue
			}
			if !item.Explicit && item.Confidence < lowestConfidence {
				lowestConfidence = item.Confidence
			}
		}
		reason := ""
		if len(missing) > 0 {
			reason = fmt.Sprintf("missing required technologies: %s; skipped without implying absence of vulnerability", strings.Join(missing, ", "))
		} else if lowestConfidence < tmpl.Prerequisites.MinimumFingerprintConfidence {
			reason = fmt.Sprintf("fingerprint confidence %d is below required %d; skipped without implying absence of vulnerability", lowestConfidence, tmpl.Prerequisites.MinimumFingerprintConfidence)
		}
		if reason == "" {
			selected = append(selected, tmpl)
			decisions = append(decisions, Decision{TemplateID: tmpl.ID, Selected: true, Required: required, Reason: "technology and minimum-confidence prerequisites satisfied"})
		} else {
			decisions = append(decisions, Decision{TemplateID: tmpl.ID, Required: required, Reason: reason})
		}
	}
	return selected, decisions
}
