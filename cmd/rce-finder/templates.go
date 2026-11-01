package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/bugbountytool/rce-finder/internal/template"
)

func runTemplates(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: rce-finder templates list|inspect|validate|verify -templates templates")
	}
	fs := flag.NewFlagSet("rce-finder templates "+args[0], flag.ContinueOnError)
	dir := fs.String("templates", "templates", "local template directory")
	id := fs.String("id", "", "template ID to inspect")
	unsigned := fs.Bool("allow-unsigned-local-templates", false, "allow explicitly local unsigned templates during an active scan")
	keys := fs.String("trusted-keys", "", "local trusted Ed25519 public keys JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		templates, err := template.LoadDir(*dir)
		if err != nil {
			return err
		}
		for _, tmpl := range templates {
			fmt.Fprintf(cliStdout, "%s\t%s\t%s\n", tmpl.ID, tmpl.Severity, tmpl.Name)
		}
		return nil
	case "inspect":
		if *id == "" {
			return fmt.Errorf("inspect requires -id")
		}
		templates, err := template.LoadDir(*dir)
		if err != nil {
			return err
		}
		for _, tmpl := range templates {
			if tmpl.ID == *id {
				encoder := json.NewEncoder(cliStdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(tmpl)
			}
		}
		return fmt.Errorf("template %q not found", *id)
	case "validate":
		templates, err := template.LoadDir(*dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(cliStdout, "validated %d local template(s)\n", len(templates))
		return nil
	case "verify":
		return template.VerifyDir(*dir, *keys, *unsigned)
	default:
		return fmt.Errorf("unknown templates command %q", args[0])
	}
}
