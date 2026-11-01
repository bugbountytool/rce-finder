package report

import (
	"encoding/csv"
	"html/template"
	"io"
	"strconv"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

func WriteCSV(w io.Writer, results []engine.Result) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"scan_id", "job_id", "probe_id", "classification", "confidence", "severity", "template_id", "target", "cwe", "cve", "detail", "remediation"}); err != nil {
		return err
	}
	for _, result := range results {
		result = sanitized(result)
		classification := result.Classification
		if classification == "" {
			classification = result.Status
		}
		if err := writer.Write([]string{result.ScanID, result.JobID, result.ProbeID, string(classification), strconv.Itoa(result.Confidence.Score), result.Severity, result.TemplateID, result.Target, join(result.CWEs), join(result.CVEs), result.Detail, result.Remediation}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func join(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ";"
		}
		out += value
	}
	return out
}

var htmlReport = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>RCE Finder report</title><style>body{font:15px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%}th,td{padding:.5rem;border:1px solid #ccd;text-align:left;vertical-align:top}th{background:#eef}code{overflow-wrap:anywhere}</style></head>
<body><h1>RCE Finder scan report</h1><p>Evidence metadata only. Request context, cookies, authorization values, canaries, and raw bodies are excluded.</p>
<table><thead><tr><th>Classification</th><th>Confidence</th><th>Severity</th><th>Template</th><th>Target</th><th>Detail</th><th>Evidence digests</th><th>Remediation</th></tr></thead><tbody>
{{range .}}<tr><td>{{.Classification}}</td><td>{{.Confidence.Score}}</td><td>{{.Severity}}</td><td>{{.TemplateID}}</td><td>{{.Target}}</td><td>{{.Detail}}</td><td>{{range .Evidence}}<code>{{.Kind}}: {{.Digest}}</code><br>{{end}}</td><td>{{.Remediation}}</td></tr>{{end}}
</tbody></table></body></html>`))

func WriteHTML(w io.Writer, results []engine.Result) error {
	safe := make([]engine.Result, len(results))
	for i, result := range results {
		safe[i] = sanitized(result)
	}
	return htmlReport.Execute(w, safe)
}
