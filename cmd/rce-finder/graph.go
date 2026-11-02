package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/bugbountytool/rce-finder/internal/graph"
	"github.com/bugbountytool/rce-finder/internal/inventory"
	"github.com/bugbountytool/rce-finder/internal/policy"
	"github.com/bugbountytool/rce-finder/internal/scope"
)

// runGraph builds a local security graph from an explicit target plus a local
// import. It performs no network I/O and never expands scope.
func runGraph(args []string) error {
	fs := flag.NewFlagSet("rce-finder graph", flag.ContinueOnError)
	targetsFile := fs.String("targets", "", "explicit target scope (required)")
	allowPrivate := fs.Bool("allow-private", false, "allow loopback/private targets for an authorized lab")
	openAPI := fs.String("openapi", "", "local OpenAPI v3 JSON to attach as endpoints")
	har := fs.String("har", "", "local HAR to attach as endpoints")
	postman := fs.String("postman", "", "local Postman collection to attach as endpoints")
	dbPath := fs.String("db", "", "SQLite graph output path (required, new file)")
	show := fs.String("show", "", "print the graph from an existing -db instead of building")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *show != "" {
		return showGraph(*show)
	}
	if *targetsFile == "" || *dbPath == "" {
		fs.Usage()
		return fmt.Errorf("graph requires -targets and -db")
	}
	scanPolicy := policy.Default()
	scanPolicy.AllowPrivate = *allowPrivate
	targets, err := scope.LoadWithPolicy(*targetsFile, scanPolicy)
	if err != nil {
		return err
	}
	store, err := graph.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	var eps []inventory.Endpoint
	switch {
	case *openAPI != "":
		eps, err = inventory.LoadOpenAPIJSON(*openAPI)
	case *har != "":
		eps, err = inventory.LoadHARJSON(*har, targets)
	case *postman != "":
		eps, err = inventory.LoadPostmanJSON(*postman, targets)
	}
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := graph.BuildFromInventory(store, target.Raw, eps); err != nil {
			return err
		}
	}
	counts, _ := store.Counts()
	enc := json.NewEncoder(cliStdout)
	enc.SetIndent("", "  ")
	fmt.Fprintf(cliStderr, "built security graph at %s\n", *dbPath)
	return enc.Encode(counts)
}

func showGraph(path string) error {
	store, err := graph.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()
	enc := json.NewEncoder(cliStdout)
	enc.SetIndent("", "  ")
	for _, kind := range []graph.NodeKind{graph.NodeAsset, graph.NodeEndpoint, graph.NodeSource, graph.NodeSink} {
		nodes, err := store.NodesByKind(kind)
		if err != nil {
			return err
		}
		for _, n := range nodes {
			if err := enc.Encode(n); err != nil {
				return err
			}
		}
	}
	return nil
}
