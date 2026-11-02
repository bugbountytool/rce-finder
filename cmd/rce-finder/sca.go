package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/bugbountytool/rce-finder/internal/intel"
	"github.com/bugbountytool/rce-finder/internal/sca"
)

// runSCA parses a local dependency manifest, queries OSV for affected versions,
// and reports applicability assessments. It never claims a confirmed
// vulnerability from a version match.
func runSCA(args []string) error {
	fs := flag.NewFlagSet("rce-finder sca", flag.ContinueOnError)
	gomod := fs.String("gomod", "", "local go.mod to analyze")
	npm := fs.String("package-lock", "", "local package-lock.json to analyze")
	pypi := fs.String("requirements", "", "local requirements.txt to analyze")
	query := fs.Bool("query-osv", false, "query the OSV API for affected versions (network)")
	timeout := fs.Duration("timeout", 30*time.Second, "OSV query timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var deps []sca.Dependency
	var err error
	switch {
	case *gomod != "":
		deps, err = sca.ParseGoMod(*gomod)
	case *npm != "":
		deps, err = sca.ParsePackageLock(*npm)
	case *pypi != "":
		deps, err = sca.ParseRequirements(*pypi)
	default:
		fs.Usage()
		return fmt.Errorf("sca requires one of -gomod, -package-lock, -requirements")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(cliStderr, "parsed %d dependencies\n", len(deps))
	enc := json.NewEncoder(cliStdout)
	enc.SetIndent("", "  ")
	if !*query {
		return enc.Encode(deps)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client := intel.NewOSVClient()
	for _, d := range deps {
		advisories, err := client.Query(ctx, d.Ecosystem, d.Name, d.Version)
		if err != nil {
			fmt.Fprintf(cliStderr, "osv query %s: %v\n", d.Name, err)
			continue
		}
		for _, a := range advisories {
			as := intel.Assess(a, false, intel.ThreatContext{})
			_ = enc.Encode(map[string]any{"dependency": d, "assessment": as})
		}
	}
	return nil
}
