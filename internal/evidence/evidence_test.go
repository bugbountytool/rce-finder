package evidence

import (
	"testing"
	"time"
)

func TestDigestIsStableRegardlessOfAttributeOrder(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := New(KindInteraction, "p", at, map[string]string{"protocol": "dns", "source": "127.0.0.1"})
	b := New(KindInteraction, "p", at, map[string]string{"source": "127.0.0.1", "protocol": "dns"})
	if a.Digest != b.Digest || len(a.Digest) != 64 {
		t.Fatalf("unstable digest: %q / %q", a.Digest, b.Digest)
	}
}
