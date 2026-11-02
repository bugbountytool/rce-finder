package gosast

import (
	"testing"
)

func TestDefaultRulesCoverCommandAndSQLInjection(t *testing.T) {
	rules := DefaultRules()
	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.ID] = true
		if len(r.Sources) == 0 || len(r.Sinks) == 0 {
			t.Errorf("rule %s missing sources or sinks", r.ID)
		}
		if r.CWE == "" {
			t.Errorf("rule %s missing CWE", r.ID)
		}
	}
	if !ids["go-command-injection"] || !ids["go-sql-injection"] {
		t.Fatalf("default rules = %v", ids)
	}
}

func TestMatcherFields(t *testing.T) {
	m := Matcher{Pkg: "os/exec", Func: "Command"}
	if m.Pkg != "os/exec" || m.Func != "Command" {
		t.Fatalf("matcher = %+v", m)
	}
}
