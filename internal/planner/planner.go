// Package planner selects the smallest applicable set of templates. It never
// creates targets or discovers technology over the network.
package planner

import (
	"strings"

	"github.com/bugbountytool/rce-finder/internal/template"
)

// SelectByTechnologies returns all templates when no technologies are supplied.
// Otherwise, it selects templates with an overlapping declared tag.
func SelectByTechnologies(templates []*template.Template, technologies []string) []*template.Template {
	want := make(map[string]struct{}, len(technologies))
	for _, item := range technologies {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			want[item] = struct{}{}
		}
	}
	if len(want) == 0 {
		return templates
	}
	selected := make([]*template.Template, 0, len(templates))
	for _, tmpl := range templates {
		for _, tag := range tmpl.Technologies {
			if _, ok := want[strings.ToLower(tag)]; ok {
				selected = append(selected, tmpl)
				break
			}
		}
	}
	return selected
}

func ParseTechnologies(value string) []string { return strings.Split(value, ",") }
