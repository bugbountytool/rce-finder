package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bugbountytool/rce-finder/internal/report"
	"github.com/bugbountytool/rce-finder/internal/storage"
)

func runReport(args []string) error {
	fs := flag.NewFlagSet("rce-finder report", flag.ContinueOnError)
	snapshot := fs.String("snapshot", "", "stored local result snapshot (required)")
	format := fs.String("format", "markdown", "markdown, json, sarif, html, or csv")
	output := fs.String("output", "", "new output file; stdout when empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *snapshot == "" {
		return fmt.Errorf("report requires -snapshot")
	}
	stored, err := storage.ReadSnapshot(*snapshot)
	if err != nil {
		return err
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
	switch strings.ToLower(*format) {
	case "markdown":
		return report.WriteMarkdown(out, stored.Results)
	case "json":
		for _, result := range stored.Results {
			if err := report.NewJSONWriter(out).Write(result); err != nil {
				return err
			}
		}
		return nil
	case "sarif":
		return report.WriteSARIF(out, stored.Results)
	case "html":
		return report.WriteHTML(out, stored.Results)
	case "csv":
		return report.WriteCSV(out, stored.Results)
	default:
		return fmt.Errorf("unsupported report format %q", *format)
	}
}
