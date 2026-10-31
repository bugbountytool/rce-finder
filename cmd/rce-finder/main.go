// Command rce-finder is a template-driven, OOB-confirmation RCE scanner
// intended for authorized security testing (bug bounty programs, internal
// pentests, CI security gates on your own services).
//
// It will NEVER discover targets on its own: you must supply an explicit
// target file, and by running this tool against those targets you are
// representing that you are authorized to test them. See SECURITY.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/inventory"
	"github.com/bugbountytool/rce-finder/internal/oob"
	"github.com/bugbountytool/rce-finder/internal/planner"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/report"
	"github.com/bugbountytool/rce-finder/internal/requestctx"
	"github.com/bugbountytool/rce-finder/internal/scope"
	"github.com/bugbountytool/rce-finder/internal/storage"
	"github.com/bugbountytool/rce-finder/internal/template"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("rce-finder", flag.ExitOnError)
	var (
		targetsFile   = fs.String("targets", "", "path to file of explicitly in-scope target URLs, one per line (required)")
		templatesDir  = fs.String("templates", "templates", "directory of vulnerability check templates")
		oobBaseURL    = fs.String("oob-server", "", "base URL of a self-hosted OOB interaction server (see docs/OOB.md); if empty, a local stub is used that never reports hits")
		oobDomain     = fs.String("oob-domain", "", "base domain for canary tokens when using the local stub client")
		concurrency   = fs.Int("concurrency", 5, "number of concurrent workers")
		rps           = fs.Float64("rate", 2.0, "max requests per second (global, conservative by default)")
		dryRun        = fs.Bool("dry-run", false, "build requests but do not send them; useful for reviewing what a scan would do")
		allowPrivate  = fs.Bool("allow-private", false, "allow loopback/private targets for an explicitly authorized lab")
		jsonOut       = fs.Bool("json", false, "emit JSON lines instead of a human-readable table")
		sarifOut      = fs.String("sarif", "", "write findings to a new SARIF 2.1.0 file")
		resultsOut    = fs.String("results", "", "write an immutable local scan-results JSON snapshot")
		markdownOut   = fs.String("markdown", "", "write findings to a new Markdown report")
		technologies  = fs.String("technologies", "", "comma-separated technology tags to select applicable templates only")
		openAPI       = fs.String("openapi", "", "inspect a local OpenAPI v3 JSON file; inventory only")
		headers       multiFlag
		iAmAuthorized = fs.Bool("i-am-authorized", false, "required acknowledgement that you have explicit authorization to test every target in --targets")
	)
	fs.Var(&headers, "header", "additional request header, repeatable: 'Name: value'")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `RCE Finder - template-driven, OOB-confirmation RCE scanner for authorized security testing

Usage:
  rce-finder -targets targets.txt -i-am-authorized [flags]

This tool will not scan anything you do not explicitly list in -targets, and
requires -i-am-authorized as an explicit acknowledgement that you hold
authorization (e.g. a bug bounty program scope, a signed pentest agreement,
or ownership) for every target in that file. See SECURITY.md.

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *targetsFile == "" {
		fs.Usage()
		return fmt.Errorf("-targets is required")
	}
	if !*iAmAuthorized {
		return fmt.Errorf("refusing to run: pass -i-am-authorized to confirm you have explicit authorization to test every target in %s (see SECURITY.md)", *targetsFile)
	}
	if *openAPI != "" {
		endpoints, err := inventory.LoadOpenAPIJSON(*openAPI)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "loaded %d declared endpoint(s) from %s; inventory is not automatically scanned\n", len(endpoints), *openAPI)
	}

	scanPolicy := policy.Default()
	scanPolicy.AllowPrivate = *allowPrivate
	targets, err := scope.LoadWithPolicy(*targetsFile, scanPolicy)
	if err != nil {
		return fmt.Errorf("loading targets: %w", err)
	}
	fmt.Fprintf(os.Stderr, "loaded %d in-scope target(s) from %s\n", len(targets), *targetsFile)

	templates, err := template.LoadDir(*templatesDir)
	if err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}
	templates = planner.SelectByTechnologies(templates, planner.ParseTechnologies(*technologies))
	if len(templates) == 0 {
		return fmt.Errorf("no templates match -technologies=%q", *technologies)
	}
	fmt.Fprintf(os.Stderr, "loaded %d template(s) from %s\n", len(templates), *templatesDir)

	var oobClient oob.Client
	if *oobBaseURL != "" {
		oobClient = oob.NewHTTPPollingClient(*oobBaseURL)
	} else {
		fmt.Fprintln(os.Stderr, "warning: no -oob-server configured; using local stub client, which NEVER reports a confirmed hit. Results will all be NOT_VULNERABLE or ERROR. See docs/OOB.md to wire up a real interaction server.")
		oobClient = oob.NewLocalStubClient(*oobDomain)
	}
	defer oobClient.Close()

	opts := engine.DefaultOptions()
	opts.Concurrency = *concurrency
	opts.RequestsPerSec = *rps
	opts.DryRun = *dryRun
	opts.Policy = scanPolicy
	opts.Headers, err = requestctx.Headers(headers)
	if err != nil {
		return fmt.Errorf("validating request headers: %w", err)
	}

	eng := engine.New(oobClient, opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nreceived interrupt, stopping after in-flight requests...")
		cancel()
	}()

	results := eng.Run(ctx, targets, templates)

	var allResults []engine.Result
	if *jsonOut {
		w := report.NewJSONWriter(os.Stdout)
		for r := range results {
			allResults = append(allResults, r)
			if err := w.Write(r); err != nil {
				return err
			}
		}
	} else {
		w := report.NewTableWriter(os.Stdout)
		for r := range results {
			allResults = append(allResults, r)
			if err := w.Write(r); err != nil {
				return err
			}
		}
		fmt.Fprint(os.Stderr, w.Summary())
	}
	if *sarifOut != "" {
		f, err := os.OpenFile(*sarifOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("creating SARIF output: %w", err)
		}
		defer f.Close()
		if err := report.WriteSARIF(f, allResults); err != nil {
			return fmt.Errorf("writing SARIF output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote SARIF findings to %s\n", *sarifOut)
	}
	if *resultsOut != "" {
		if err := storage.WriteSnapshot(*resultsOut, allResults); err != nil {
			return fmt.Errorf("writing results snapshot: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote results snapshot to %s\n", *resultsOut)
	}
	if *markdownOut != "" {
		f, err := os.OpenFile(*markdownOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("creating Markdown report: %w", err)
		}
		defer f.Close()
		if err := report.WriteMarkdown(f, allResults); err != nil {
			return fmt.Errorf("writing Markdown report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote Markdown report to %s\n", *markdownOut)
	}
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string         { return "" }
func (m *multiFlag) Set(value string) error { *m = append(*m, value); return nil }
