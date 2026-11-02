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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/fingerprint"
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
		fmt.Fprintln(cliStderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "inventory", "discover":
			return runInventory(args[1:])
		case "fingerprint":
			return runFingerprint(args[1:])
		case "graph":
			return runGraph(args[1:])
		case "sca":
			return runSCA(args[1:])
		case "templates":
			return runTemplates(args[1:])
		case "report":
			return runReport(args[1:])
		case "scan":
			args = args[1:]
		}
	}
	return runScan(args)
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("rce-finder", flag.ExitOnError)
	var (
		targetsFile   = fs.String("targets", "", "path to file of explicitly in-scope target URLs, one per line (required)")
		templatesDir  = fs.String("templates", "templates", "directory of vulnerability check templates")
		trustedKeys   = fs.String("trusted-template-keys", "", "local JSON trusted Ed25519 template public keys")
		allowUnsigned = fs.Bool("allow-unsigned-local-templates", false, "allow explicitly local unsigned templates")
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
		autoTech      = fs.Bool("auto-select-technologies", false, "select technology-tagged templates using observed/explicit technology tags")
		fingerprints  = fs.String("fingerprints", "", "local JSON fingerprint observations for explainable planning")
		explain       = fs.Bool("explain-plan", false, "print why each template was selected or skipped")
		openAPI       = fs.String("openapi", "", "inspect a local OpenAPI v3 JSON file; inventory only")
		hostRPS       = fs.Float64("host-rate", 1.0, "max requests per second for each host")
		retries       = fs.Int("retries", 2, "maximum retries for transient network errors only")
		errorBudget   = fs.Int("host-error-budget", 5, "stop a host after this many transient network errors")
		progress      = fs.Bool("progress", false, "emit redacted structured scheduler events to stderr")
		failOn        = fs.String("fail-on", "", "CI exit policy: confirmed or high-confidence")
		failSeverity  = fs.String("fail-severity", "", "minimum severity for CI failure: medium, high, critical")
		resume        = fs.String("resume", "", "resume a matching results snapshot without resending completed jobs")
		headers       multiFlag
		cookies       multiFlag
		iAmAuthorized = fs.Bool("i-am-authorized", false, "required acknowledgement that you have explicit authorization to test every target in --targets")
	)
	fs.Var(&headers, "header", "additional request header, repeatable: 'Name: value'")
	fs.Var(&cookies, "cookie", "in-memory session cookie, repeatable: 'name=value'; values are never reported or logged")
	fs.Usage = func() {
		fmt.Fprintln(cliStderr, `RCE Finder - template-driven, OOB-confirmation RCE scanner for authorized security testing

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
	if *concurrency < 1 || *rps <= 0 || *hostRPS <= 0 || *retries < 0 || *retries > 5 || *errorBudget < 1 {
		return fmt.Errorf("concurrency/rates/error budget must be positive and retries must be between 0 and 5")
	}
	if *failOn != "" && *failOn != "confirmed" && *failOn != "high-confidence" {
		return fmt.Errorf("-fail-on must be confirmed or high-confidence")
	}
	if *failSeverity != "" && *failSeverity != "medium" && *failSeverity != "high" && *failSeverity != "critical" {
		return fmt.Errorf("-fail-severity must be medium, high, or critical")
	}
	if !*iAmAuthorized {
		return fmt.Errorf("refusing to run: pass -i-am-authorized to confirm you have explicit authorization to test every target in %s (see SECURITY.md)", *targetsFile)
	}
	if *openAPI != "" {
		endpoints, err := inventory.LoadOpenAPIJSON(*openAPI)
		if err != nil {
			return err
		}
		fmt.Fprintf(cliStderr, "loaded %d declared endpoint(s) from %s; inventory is not automatically scanned\n", len(endpoints), *openAPI)
	}

	scanPolicy := policy.Default()
	scanPolicy.AllowPrivate = *allowPrivate
	policyFingerprint := engine.PolicyFingerprint(scanPolicy, *allowUnsigned)
	if *resume != "" {
		if *resultsOut != "" && *resultsOut != *resume {
			return fmt.Errorf("-results must equal -resume when resuming")
		}
		*resultsOut = *resume
	}
	targets, err := scope.LoadWithPolicy(*targetsFile, scanPolicy)
	if err != nil {
		return fmt.Errorf("loading targets: %w", err)
	}
	fmt.Fprintf(cliStderr, "loaded %d in-scope target(s) from %s\n", len(targets), *targetsFile)

	templates, err := template.LoadDir(*templatesDir)
	if err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}
	if err := template.VerifyDir(*templatesDir, *trustedKeys, *allowUnsigned); err != nil {
		return fmt.Errorf("verifying templates: %w", err)
	}
	techTags := planner.ParseTechnologies(*technologies)
	var techEvidence []planner.TechnologyEvidence
	for _, tag := range techTags {
		if tag = strings.TrimSpace(tag); tag != "" {
			techEvidence = append(techEvidence, planner.TechnologyEvidence{Name: tag, Confidence: 100, Explicit: true})
		}
	}
	if *fingerprints != "" {
		data, err := os.ReadFile(*fingerprints)
		if err != nil {
			return fmt.Errorf("reading fingerprints: %w", err)
		}
		var records []fingerprint.Record
		if err := json.Unmarshal(data, &records); err != nil {
			return fmt.Errorf("parsing local fingerprints: %w", err)
		}
		for _, record := range records {
			for _, tag := range record.Technologies() {
				techEvidence = append(techEvidence, planner.TechnologyEvidence{Name: tag, Confidence: record.ConfidenceScore()})
			}
		}
	}
	templates, decisions := planner.Select(templates, techEvidence, *autoTech || *technologies != "")
	if *explain {
		encoder := json.NewEncoder(cliStderr)
		for _, decision := range decisions {
			_ = encoder.Encode(decision)
		}
	}
	if len(templates) == 0 {
		return fmt.Errorf("no templates match -technologies=%q", *technologies)
	}
	fmt.Fprintf(cliStderr, "loaded %d template(s) from %s\n", len(templates), *templatesDir)

	var oobClient oob.Client
	if *oobBaseURL != "" {
		oobClient = oob.NewHTTPPollingClient(*oobBaseURL)
	} else {
		fmt.Fprintln(cliStderr, "warning: no -oob-server configured; using local stub client, which NEVER reports a confirmed hit. Results will all be NOT_VULNERABLE or ERROR. See docs/OOB.md to wire up a real interaction server.")
		oobClient = oob.NewLocalStubClient(*oobDomain)
	}
	defer oobClient.Close()

	opts := engine.DefaultOptions()
	opts.Concurrency = *concurrency
	opts.RequestsPerSec = *rps
	opts.DryRun = *dryRun
	opts.HostErrorBudget = *errorBudget
	opts.PerHostRPS = *hostRPS
	opts.MaxRetries = *retries
	opts.RetryBackoff = 250 * time.Millisecond
	opts.ScanID = uuid.NewString()
	if *resume != "" {
		previous, err := storage.ReadSnapshot(*resume)
		if err != nil {
			return fmt.Errorf("loading resume snapshot: %w", err)
		}
		opts.ScanID = previous.ScanID
	}
	if *progress {
		encoder := json.NewEncoder(cliStderr)
		opts.Progress = func(event engine.ProgressEvent) { _ = encoder.Encode(event) }
	}
	opts.Policy = scanPolicy
	opts.Headers, err = requestctx.Headers(headers)
	if err != nil {
		return fmt.Errorf("validating request headers: %w", err)
	}
	var cookieHosts []string
	for _, target := range targets {
		cookieHosts = append(cookieHosts, target.URL.Host)
	}
	opts.CookieJar, err = requestctx.CookiesForHosts(cookies, cookieHosts)
	if err != nil {
		return err
	}

	eng := engine.New(oobClient, opts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(cliStderr, "\nreceived interrupt, stopping after in-flight requests...")
		cancel()
	}()

	var allResults []engine.Result
	completed := make(map[string]bool)
	resumed := false
	scanJobs := engine.Jobs(targets, templates)
	if *resume != "" {
		previous, err := storage.ReadSnapshot(*resume)
		if err != nil {
			return fmt.Errorf("loading resume snapshot: %w", err)
		}
		if previous.ScopeFingerprint != engine.ScopeFingerprint(targets) || previous.TemplateFingerprint != engine.TemplateFingerprint(templates) || previous.PolicyFingerprint != policyFingerprint {
			return fmt.Errorf("resume snapshot scope, template, or policy fingerprint does not match this scan")
		}
		for _, id := range previous.CompletedJobIDs {
			completed[id] = true
		}
		for _, result := range previous.Results {
			if result.JobID != "" && completed[result.JobID] {
				allResults = append(allResults, result)
			}
		}
		resumed = true
		pending := scanJobs[:0]
		for _, job := range scanJobs {
			if !completed[job.ID] {
				pending = append(pending, job)
			}
		}
		scanJobs = pending
	}
	if !resumed && *resultsOut != "" {
		if err := storage.WriteJobSnapshot(*resultsOut, storage.Snapshot{ScanID: opts.ScanID, ScopeFingerprint: engine.ScopeFingerprint(targets), TemplateFingerprint: engine.TemplateFingerprint(templates), PolicyFingerprint: policyFingerprint, Results: []engine.Result{}, CompletedJobIDs: []string{}}); err != nil {
			return fmt.Errorf("creating results snapshot: %w", err)
		}
	}
	persist := func() error {
		if *resultsOut == "" {
			return nil
		}
		ids := make([]string, 0, len(completed))
		for id := range completed {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		snapshot := storage.Snapshot{ScanID: opts.ScanID, ScopeFingerprint: engine.ScopeFingerprint(targets), TemplateFingerprint: engine.TemplateFingerprint(templates), PolicyFingerprint: policyFingerprint, CompletedJobIDs: ids, Results: allResults}
		return storage.UpdateJobSnapshot(*resultsOut, snapshot)
	}
	results := eng.RunJobs(ctx, scanJobs)
	// Persist at most once per interval rather than on every result, which
	// would re-serialize the whole snapshot O(n) times for n results.
	const persistInterval = 2 * time.Second
	lastPersist := time.Now()
	writeResult := func(w interface{ Write(engine.Result) error }, r engine.Result) error {
		allResults = append(allResults, r)
		if engine.Completed(r) {
			completed[r.JobID] = true
		}
		if err := w.Write(r); err != nil {
			return err
		}
		if time.Since(lastPersist) >= persistInterval {
			lastPersist = time.Now()
			return persist()
		}
		return nil
	}
	if *jsonOut {
		w := report.NewJSONWriter(cliStdout)
		for r := range results {
			if err := writeResult(w, r); err != nil {
				return err
			}
		}
	} else {
		w := report.NewTableWriter(cliStdout)
		for r := range results {
			if err := writeResult(w, r); err != nil {
				return err
			}
		}
		fmt.Fprint(cliStderr, w.Summary())
	}
	if err := persist(); err != nil {
		return fmt.Errorf("persisting results snapshot: %w", err)
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
		fmt.Fprintf(cliStderr, "wrote SARIF findings to %s\n", *sarifOut)
	}
	if *resultsOut != "" {
		fmt.Fprintf(cliStderr, "wrote results snapshot to %s\n", *resultsOut)
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
		fmt.Fprintf(cliStderr, "wrote Markdown report to %s\n", *markdownOut)
	}
	if *failOn != "" {
		if report.ShouldFail(allResults, *failOn, *failSeverity) {
			return fmt.Errorf("CI policy: %s finding at or above severity %q", *failOn, *failSeverity)
		}
	}
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string         { return "" }
func (m *multiFlag) Set(value string) error { *m = append(*m, value); return nil }
