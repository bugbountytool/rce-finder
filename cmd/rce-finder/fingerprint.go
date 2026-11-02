package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bugbountytool/rce-finder/internal/fingerprint"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/redact"
	"github.com/bugbountytool/rce-finder/internal/requestctx"
	"github.com/bugbountytool/rce-finder/internal/scope"
)

func runFingerprint(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return fingerprintWithContext(ctx, args)
}

func fingerprintWithContext(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rce-finder fingerprint", flag.ContinueOnError)
	targetsFile := fs.String("targets", "", "file containing exact explicitly scoped URLs to request")
	allowPrivate := fs.Bool("allow-private", false, "allow loopback/private targets for an explicitly authorized lab")
	authorized := fs.Bool("i-am-authorized", false, "confirm authorization for every explicit target")
	includeBody := fs.Bool("body-signatures", false, "record a body hash and limited passive body signatures; maximum 1 MiB")
	output := fs.String("output", "", "write new JSON fingerprint observations")
	rate := fs.Float64("rate", 1.0, "maximum fingerprint requests per second")
	var headers, cookies multiFlag
	fs.Var(&headers, "header", "additional request header, repeatable: 'Name: value'")
	fs.Var(&cookies, "cookie", "in-memory secure session cookie, repeatable: 'name=value'")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetsFile == "" || !*authorized {
		return fmt.Errorf("fingerprint requires -targets and -i-am-authorized; only explicitly listed URLs are requested")
	}
	if *rate <= 0 || *rate > 100 || math.IsNaN(*rate) || math.IsInf(*rate, 0) {
		return fmt.Errorf("fingerprint -rate must be greater than 0 and no more than 100")
	}
	scanPolicy := policy.Default()
	scanPolicy.AllowPrivate = *allowPrivate
	targets, err := scope.LoadWithPolicy(*targetsFile, scanPolicy)
	if err != nil {
		return err
	}
	header, err := requestctx.Headers(headers)
	if err != nil {
		return err
	}
	var cookieHosts []string
	for _, target := range targets {
		cookieHosts = append(cookieHosts, target.URL.Host)
	}
	jar, err := requestctx.CookiesForHosts(cookies, cookieHosts)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	interval := time.Duration(float64(time.Second) / *rate)
	var lastRequest time.Time
	var records []fingerprint.Record
	for _, target := range targets {
		if !lastRequest.IsZero() {
			if err := waitInterval(ctx, interval-time.Since(lastRequest)); err != nil {
				return fmt.Errorf("fingerprinting cancelled: %w", err)
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL.String(), nil)
		if err != nil {
			return fmt.Errorf("building fingerprint request: %w", err)
		}
		req.Header = header.Clone()
		req.Header.Set("User-Agent", "rce-finder/0.1 (+authorized-security-testing)")
		lastRequest = time.Now()
		resp, err := client.Do(req)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return fmt.Errorf("fingerprinting cancelled: %w", ctxErr)
			}
			return fmt.Errorf("fingerprinting explicit target %s: %s", redact.URL(target.Raw), redact.Text(err.Error()))
		}
		record, readErr := fingerprint.ReadResponse(redact.URL(target.Raw), resp, 1<<20, *includeBody)
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("reading fingerprint response: %s", redact.Text(readErr.Error()))
		}
		records = append(records, record)
		data, _ := json.Marshal(record)
		fmt.Fprintln(cliStdout, string(data))
	}
	if *output != "" {
		data, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNewFile(*output, append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
