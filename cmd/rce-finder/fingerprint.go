package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/bugbountytool/rce-finder/internal/fingerprint"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/requestctx"
	"github.com/bugbountytool/rce-finder/internal/scope"
)

func runFingerprint(args []string) error {
	fs := flag.NewFlagSet("rce-finder fingerprint", flag.ContinueOnError)
	targetsFile := fs.String("targets", "", "file containing exact explicitly scoped URLs to request")
	allowPrivate := fs.Bool("allow-private", false, "allow loopback/private targets for an explicitly authorized lab")
	authorized := fs.Bool("i-am-authorized", false, "confirm authorization for every explicit target")
	includeBody := fs.Bool("body-signatures", false, "record a body hash and limited passive body signatures; maximum 1 MiB")
	output := fs.String("output", "", "write new JSON fingerprint observations")
	var headers, cookies multiFlag
	fs.Var(&headers, "header", "additional request header, repeatable: 'Name: value'")
	fs.Var(&cookies, "cookie", "in-memory secure session cookie, repeatable: 'name=value'")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetsFile == "" || !*authorized {
		return fmt.Errorf("fingerprint requires -targets and -i-am-authorized; only explicitly listed URLs are requested")
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
	var records []fingerprint.Record
	for _, target := range targets {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target.URL.String(), nil)
		if err != nil {
			return err
		}
		req.Header = header.Clone()
		req.Header.Set("User-Agent", "rce-finder/0.1 (+authorized-security-testing)")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("fingerprinting explicit target %s: %w", target.Raw, err)
		}
		record, readErr := fingerprint.ReadResponse(target.Raw, resp, 1<<20, *includeBody)
		resp.Body.Close()
		if readErr != nil {
			return readErr
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
