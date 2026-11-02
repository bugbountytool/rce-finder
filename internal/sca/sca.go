// Package sca performs software composition analysis: it parses dependency
// manifests and lockfiles, queries vulnerability intelligence, and labels each
// dependency finding with a reachability status. A vulnerable version alone is
// an applicability match, never a confirmed vulnerability.
package sca

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

// Dependency is one resolved package.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string // OSV ecosystem: "Go", "npm", "PyPI"
	Direct    bool
}

// ParseGoMod extracts module requirements from a go.mod file.
func ParseGoMod(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Dependency
	inRequire := false
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		var entry string
		if inRequire {
			entry = line
		} else if strings.HasPrefix(line, "require ") {
			entry = strings.TrimPrefix(line, "require ")
		} else {
			continue
		}
		entry = strings.Split(entry, "//")[0]
		fields := strings.Fields(entry)
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "v") {
			out = append(out, Dependency{
				Name: fields[0], Version: fields[1], Ecosystem: "Go",
				Direct: !strings.Contains(line, "// indirect"),
			})
		}
	}
	return out, scanner.Err()
}

// package-lock.json v2/v3 structure.
type packageLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

// ParsePackageLock extracts dependencies from an npm package-lock.json.
func ParsePackageLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Dependency
	for name, pkg := range lock.Packages {
		if name == "" || pkg.Version == "" {
			continue
		}
		// keys look like "node_modules/<pkg>" possibly nested
		parts := strings.Split(name, "node_modules/")
		pkgName := parts[len(parts)-1]
		out = append(out, Dependency{Name: pkgName, Version: pkg.Version, Ecosystem: "npm"})
	}
	return out, nil
}

var reqRe = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*==\s*([0-9][^;\s]*)`)

// ParseRequirements extracts pinned dependencies from a requirements.txt.
func ParseRequirements(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Dependency
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := reqRe.FindStringSubmatch(line); m != nil {
			out = append(out, Dependency{Name: m[1], Version: m[2], Ecosystem: "PyPI"})
		}
	}
	return out, scanner.Err()
}
