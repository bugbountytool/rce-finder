package planner

import (
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/template"
)

func TestAutoSelectionExplainsConfidenceAndMissingTechnology(t *testing.T) {
	tmpl := &template.Template{ID: "java", Technologies: []string{"java"}, Prerequisites: template.Prerequisites{MinimumFingerprintConfidence: 50}}
	selected, decisions := Select([]*template.Template{tmpl}, []TechnologyEvidence{{Name: "java", Confidence: 30}}, true)
	if len(selected) != 0 || len(decisions) != 1 || !strings.Contains(decisions[0].Reason, "below required") {
		t.Fatalf("low-confidence plan = %#v %#v", selected, decisions)
	}
	selected, decisions = Select([]*template.Template{tmpl}, []TechnologyEvidence{{Name: "java", Confidence: 60}}, true)
	if len(selected) != 1 || !decisions[0].Selected {
		t.Fatalf("satisfied plan = %#v %#v", selected, decisions)
	}
	selected, _ = Select([]*template.Template{tmpl}, nil, false)
	if len(selected) != 1 {
		t.Fatal("default planning filtered an explicitly selected template")
	}
}
