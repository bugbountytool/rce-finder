package report

import (
	"github.com/bugbountytool/rce-finder/internal/engine"
	"github.com/bugbountytool/rce-finder/internal/redact"
)

func sanitized(result engine.Result) engine.Result {
	result.Detail = redact.Text(result.Detail, result.Canary)
	result.Canary = ""
	if result.Classification == "" {
		result.Classification = result.Status
	}
	result.Target = redact.URL(result.Target)
	return result
}
