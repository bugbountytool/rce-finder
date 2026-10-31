package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

func TestWriteMarkdownEscapesAndRedactsTableValues(t *testing.T) {
	var out bytes.Buffer
	if err := WriteMarkdown(&out, []engine.Result{{Status: engine.StatusConfirmed, TemplateID: "x|y", Canary: "token.oob.test", Detail: "callback token.oob.test"}}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "# RCE Finder scan report") || !strings.Contains(got, "x\\|y") || strings.Contains(got, "token.oob.test") || !strings.Contains(got, "[redacted-canary]") {
		t.Fatalf("markdown = %q", got)
	}
}
