package mobile

import (
	"testing"
)

func TestScanDEXStringsFindsRiskyAPIs(t *testing.T) {
	dex := []byte("dex\n035\x00....addJavascriptInterface....X509TrustManager....MODE_WORLD_READABLE....")
	risks := ScanDEXStrings(dex)
	apis := map[string]bool{}
	for _, r := range risks {
		apis[r.API] = true
	}
	for _, want := range []string{"addJavascriptInterface", "custom-trust-manager", "world-readable"} {
		if !apis[want] {
			t.Errorf("API %s not detected; got %v", want, apis)
		}
	}
}

func TestScanDEXStringsNoFalsePositiveOnClean(t *testing.T) {
	dex := []byte("dex\n035\x00....ordinaryMethodName....anotherMethod....")
	if risks := ScanDEXStrings(dex); len(risks) != 0 {
		t.Fatalf("false positives on clean DEX: %+v", risks)
	}
}

func TestIsDEX(t *testing.T) {
	if !IsDEX([]byte("dex\n035\x00....")) {
		t.Fatal("DEX magic not recognized")
	}
	if IsDEX([]byte("PK\x03\x04")) {
		t.Fatal("ZIP misidentified as DEX")
	}
}
