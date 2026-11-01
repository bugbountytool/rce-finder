package labfixture

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Server is a deliberately non-executing fixture. It recognizes a canary in a
// declared text field and, only in vulnerable mode, asks the local fake OOB
// server to record a callback. It never evaluates template source or commands.
type Server struct {
	Vulnerable bool
	Callback   func(string)
	Mode       string
	Requests   int
	mu         sync.Mutex
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.Requests++
	s.mu.Unlock()
	if s.Mode == "redirect" {
		w.Header().Set("Location", "https://outside-scope.invalid/")
		w.WriteHeader(http.StatusFound)
		return
	}
	if s.Mode == "waf" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if s.Mode == "malformed" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var values map[string]string
	_ = json.Unmarshal(body, &values)
	canary := ""
	for _, value := range values {
		if index := strings.Index(value, ".oob.test"); index > 0 {
			prefix := value[:index]
			start := strings.LastIndex(prefix, "/") + 1
			canary = prefix[start:] + ".oob.test"
		}
	}
	if canary == "" {
		canary = r.URL.Query().Get("q")
		if start := strings.Index(canary, "://"); start >= 0 {
			canary = canary[start+3:]
		}
		if end := strings.Index(canary, "/"); end >= 0 {
			canary = canary[:end]
		}
	}
	if s.Vulnerable && strings.HasSuffix(canary, ".oob.test") && s.Callback != nil {
		s.Callback(canary)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"evaluated": s.Vulnerable && canary != "", "patched": !s.Vulnerable})
}
