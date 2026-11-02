// Command govuln is a deliberately vulnerable Go HTTP service used only as a
// static-analysis and dynamic-detection test fixture. It is never deployed and
// never scanned outside a local lab. The vulnerable handler passes an
// attacker-controlled query value into os/exec without validation.
package main

import (
	"net/http"
	"os/exec"
)

// vulnerable is the positive fixture: r.FormValue is a source, exec.Command
// is a sink, and the value flows between them.
func vulnerable(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd") // source
	out, _ := exec.Command("sh", "-c", cmd).Output() // sink: source reaches it
	_, _ = w.Write(out)
}

// patched is the negative fixture: the sink takes a constant, not source data.
func patched(w http.ResponseWriter, r *http.Request) {
	_ = r.FormValue("cmd")
	out, _ := exec.Command("date").Output() // sink, but no source flow
	_, _ = w.Write(out)
}

func main() {
	http.HandleFunc("/vuln", vulnerable)
	http.HandleFunc("/patched", patched)
	_ = http.ListenAndServe("127.0.0.1:0", nil)
}
