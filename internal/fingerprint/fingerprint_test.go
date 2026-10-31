package fingerprint

import (
	"net/http"
	"testing"
)

func TestFromHeadersCreatesHintsOnly(t *testing.T) {
	h := make(http.Header)
	h.Set("Server", "nginx/1.25")
	h.Set("X-Powered-By", "Express")
	got := FromHeaders(h)
	if len(got) != 2 || got[0].Product != "nginx" || got[0].Version != "1.25" || got[1].Product != "express" {
		t.Fatalf("observations = %#v", got)
	}
}
