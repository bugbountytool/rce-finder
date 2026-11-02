package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bugbountytool/rce-finder/internal/analyze/gosast"
	"github.com/bugbountytool/rce-finder/internal/model"
	"github.com/bugbountytool/rce-finder/internal/report"
	"github.com/bugbountytool/rce-finder/internal/verify"
)

// runInvestigate runs the static analysis tier against a local source module,
// classifies each finding through the verification kernel, and emits a rich
// finding report. This is the source-to-sink investigation workflow: it never
// contacts a network target and never claims dynamic confirmation from static
// analysis alone.
func runInvestigate(args []string) error {
	fs := flag.NewFlagSet("rce-finder investigate", flag.ContinueOnError)
	srcDir := fs.String("source", "", "local Go module directory to analyze (required)")
	format := fs.String("format", "markdown", "markdown or json")
	output := fs.String("output", "", "new output file; stdout when empty")
	asset := fs.String("asset", "", "logical asset name for findings (default: source dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *srcDir == "" {
		fs.Usage()
		return fmt.Errorf("investigate requires -source")
	}
	if *asset == "" {
		*asset = *srcDir
	}
	findings, err := gosast.New(*srcDir).Analyze()
	if err != nil {
		return fmt.Errorf("static analysis: %w", err)
	}
	kernel := verify.New()
	var verified []model.Finding
	for _, sf := range findings {
		cand := model.Candidate{
			ID: sf.RuleID + "-" + sf.Sink.File, Title: sf.Description,
			Class: sf.Class, CWEs: []string{sf.CWE}, Asset: *asset,
			Severity: "high",
			Provenance: model.Provenance{Engine: "gosast", RuleID: sf.RuleID},
			Flow: &model.Flow{
				Source:    model.Source{Kind: "http", Name: sf.SourceName, Location: sf.Source},
				Sink:      model.Sink{Kind: sf.Class, Location: sf.Sink},
				Reachable: sf.Complete,
			},
		}
		obs := []verify.Observation{{Kind: verify.ObsStaticFlow, CompleteFlow: sf.Complete, Reachable: sf.Complete}}
		f, err := kernel.Verify(cand, obs)
		if err != nil {
			continue
		}
		f.RootCause = &model.RootCause{Class: model.ControlMissing, Basis: "source",
			Control: "input validation/encoding before the sink",
			Explanation: sf.Description,
			WeakestLink: "static reachability does not prove runtime exploitability"}
		verified = append(verified, f)
	}
	var out = os.Stdout
	if *output != "" {
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		out = file
	}
	fmt.Fprintf(cliStderr, "investigated %s: %d finding(s)\n", *srcDir, len(verified))
	switch *format {
	case "json":
		return report.WriteFindingJSONL(out, verified)
	default:
		return report.WriteFindingMarkdown(out, verified)
	}
}
