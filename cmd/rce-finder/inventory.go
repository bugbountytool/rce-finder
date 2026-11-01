package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/bugbountytool/rce-finder/internal/inventory"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/scope"
)

// runInventory only reads local files and prints endpoints. It never sends a
// request, writes a target file, or turns an import into an active scan.
func runInventory(args []string) error {
	fs := flag.NewFlagSet("rce-finder inventory", flag.ContinueOnError)
	targetsFile := fs.String("targets", "", "path to explicit HTTP(S) target scope (required)")
	allowPrivate := fs.Bool("allow-private", false, "allow loopback/private targets for an explicitly authorized lab")
	har := fs.String("har", "", "local HAR file; only final request URLs inside explicit scope are included")
	postman := fs.String("postman", "", "local Postman collection; literal URLs inside explicit scope are inventory only")
	openAPI := fs.String("openapi", "", "local OpenAPI v3 JSON file; declared paths only, no servers or references")
	jsonOut := fs.Bool("json", false, "print JSON instead of a tab-separated table")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: rce-finder inventory -targets targets.txt [-har file | -postman file | -openapi file] [-json]\n\nInventory is local-only and never sends requests or creates scan targets.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *targetsFile == "" {
		fs.Usage()
		return fmt.Errorf("inventory requires -targets and exactly one input format")
	}
	formats := 0
	for _, value := range []string{*har, *postman, *openAPI} {
		if value != "" {
			formats++
		}
	}
	if formats != 1 {
		return fmt.Errorf("choose exactly one of -har, -postman, or -openapi")
	}
	scanPolicy := policy.Default()
	scanPolicy.AllowPrivate = *allowPrivate
	targets, err := scope.LoadWithPolicy(*targetsFile, scanPolicy)
	if err != nil {
		return fmt.Errorf("loading explicit inventory scope: %w", err)
	}
	var endpoints []inventory.Endpoint
	switch {
	case *har != "":
		endpoints, err = inventory.LoadHARJSON(*har, targets)
	case *postman != "":
		endpoints, err = inventory.LoadPostmanJSON(*postman, targets)
	case *openAPI != "":
		endpoints, err = inventory.LoadOpenAPIJSON(*openAPI)
	}
	if err != nil {
		return err
	}
	if *jsonOut {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(endpoints)
	}
	fmt.Println("METHOD\tPATH\tSOURCE")
	for _, endpoint := range endpoints {
		fmt.Printf("%s\t%s\t%s\n", endpoint.Method, endpoint.Path, endpoint.Source)
	}
	fmt.Fprintf(os.Stderr, "inventoried %d endpoint(s); no network requests sent and no active scan planned\n", len(endpoints))
	return nil
}
