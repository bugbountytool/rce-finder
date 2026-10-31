package planner

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/template"
)

func TestSelectByTechnologies(t *testing.T) {
	all := []*template.Template{{ID: "java", Technologies: []string{"java", "jvm"}}, {ID: "python", Technologies: []string{"python"}}}
	got := SelectByTechnologies(all, ParseTechnologies("JVM, java"))
	if len(got) != 1 || got[0].ID != "java" {
		t.Fatalf("selected = %#v", got)
	}
	if got := SelectByTechnologies(all, nil); len(got) != 2 {
		t.Fatalf("empty filter selected %d", len(got))
	}
}
