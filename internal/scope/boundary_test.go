package scope

import (
	"net/url"
	"testing"
)

func TestContainsEndpointRejectsEncodedTraversalAndAuthorityChanges(t *testing.T) {
	target, _ := url.Parse("https://example.test/v1")
	for _, raw := range []string{
		"https://example.test/v2/items",
		"https://example.test/v1/../v2/items",
		"https://example.test/v1%2f..%2fv2/items",
		"https://example.test/v1%5c..%5cv2/items",
		"https://other.example/v1/items",
		"http://example.test/v1/items",
		"https://example.test:444/v1/items",
		"https://user:secret@example.test/v1/items",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if ContainsEndpoint(target, u) {
			t.Errorf("out-of-scope URL accepted: %s", raw)
		}
	}
	inScope, _ := url.Parse("https://example.test/v1/items?token=secret")
	if !ContainsEndpoint(target, inScope) {
		t.Fatal("valid in-scope endpoint rejected")
	}
}
