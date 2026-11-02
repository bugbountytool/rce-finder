package mobile

import (
	"regexp"
	"strings"
)

// DEXRisk describes a risky API reference found in DEX bytecode strings.
type DEXRisk struct {
	API      string
	Class    string
	CWE      string
	Severity string
	Detail   string
}

var dexRisks = []struct {
	pattern *regexp.Regexp
	risk    DEXRisk
}{
	{regexp.MustCompile(`addJavascriptInterface`), DEXRisk{"addJavascriptInterface", "webview-bridge", "CWE-749", "high",
		"WebView exposes a Java object to JavaScript in every frame without origin checks"}},
	{regexp.MustCompile(`setJavaScriptEnabled`), DEXRisk{"setJavaScriptEnabled", "webview", "CWE-749", "medium",
		"WebView enables JavaScript; review loaded content origin"}},
	{regexp.MustCompile(`setAllowFileAccess`), DEXRisk{"setAllowFileAccess", "webview-file-access", "CWE-200", "medium",
		"WebView allows file:// access"}},
	{regexp.MustCompile(`X509TrustManager|checkServerTrusted|HostnameVerifier`), DEXRisk{"custom-trust-manager", "tls-validation", "CWE-295", "high",
		"custom certificate/hostname validation may disable TLS checks"}},
	{regexp.MustCompile(`setHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER`), DEXRisk{"hostname-verifier", "tls-validation", "CWE-297", "high",
		"hostname verification may be disabled"}},
	{regexp.MustCompile(`DexClassLoader|PathClassLoader|loadClass`), DEXRisk{"dynamic-class-load", "dynamic-loading", "CWE-470", "medium",
		"dynamic class loading from an external path"}},
	{regexp.MustCompile(`MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE`), DEXRisk{"world-readable", "insecure-storage", "CWE-732", "high",
		"file or shared preferences are world-readable/writable"}},
}

// ScanDEXStrings scans raw DEX bytes for risky API/method references. This is
// string-level detection over the DEX string table and code; it indicates the
// presence of a risky API, not whether it is reachable or exploitable.
func ScanDEXStrings(dex []byte) []DEXRisk {
	// DEX strings are MUTF-8; a byte-level scan is sufficient to locate the
	// referenced method names without a full DEX parse.
	text := string(dex)
	var out []DEXRisk
	seen := map[string]bool{}
	for _, r := range dexRisks {
		if r.pattern.MatchString(text) && !seen[r.risk.API] {
			seen[r.risk.API] = true
			out = append(out, r.risk)
		}
	}
	return out
}

// IsDEX reports whether data begins with the DEX magic header.
func IsDEX(data []byte) bool {
	return len(data) >= 8 && strings.HasPrefix(string(data), "dex\n")
}
