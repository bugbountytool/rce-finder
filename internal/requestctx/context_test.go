package requestctx

import "testing"

func TestHeadersValidatesContext(t *testing.T) {
	h, err := Headers([]string{"Authorization: Bearer test"})
	if err != nil || h.Get("Authorization") != "Bearer test" {
		t.Fatalf("Headers() = %#v, %v", h, err)
	}
	if _, err := Headers([]string{"Host: bad"}); err == nil {
		t.Fatal("Host override accepted")
	}
}
