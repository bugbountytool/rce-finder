// Package laboob is an in-memory fake OOB service for local integration tests.
// It has no DNS server, public callback listener, or target discovery feature.
package laboob

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bugbountytool/rce-finder/internal/oob"
)

type Server struct {
	mu       sync.Mutex
	probes   map[string]string
	callback map[string]*oob.Interaction
	delay    time.Duration
	mismatch string
	server   *httptest.Server
	external bool
}

func New() *Server {
	s := &Server{probes: map[string]string{}, callback: map[string]*oob.Interaction{}}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string { return s.server.URL }
func (s *Server) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

func NewStandalone() *Server {
	return &Server{probes: map[string]string{}, callback: map[string]*oob.Interaction{}, external: true}
}

func StandaloneHandler() http.Handler {
	return http.HandlerFunc(NewStandalone().handle)
}

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.handle) }

func (s *Server) SetMode(mismatch string, delay time.Duration) {
	s.mu.Lock()
	s.mismatch, s.delay = mismatch, delay
	s.mu.Unlock()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/issue":
		var request struct {
			ProbeID string `json:"probe_id"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request) != nil || request.ProbeID == "" {
			http.Error(w, `{"error":"invalid issue request"}`, http.StatusBadRequest)
			return
		}
		token := randomToken()
		s.mu.Lock()
		s.probes[token+".oob.test"] = request.ProbeID
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"canary": token + ".oob.test"})
	case "/poll":
		probeID := r.URL.Query().Get("probe_id")
		s.mu.Lock()
		interaction := s.callback[probeID]
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]*oob.Interaction{"interaction": interaction})
	case "/callback/":
		s.observe(r)
	default:
		if strings.HasPrefix(r.URL.Path, "/callback/") {
			s.observe(r)
			return
		}
		http.NotFound(w, r)
	}
}

func (s *Server) observe(r *http.Request) {
	canary := r.Host
	if s.external {
		canary = strings.Split(canary, ":")[0]
	}
	if path := strings.TrimPrefix(r.URL.Path, "/callback/"); path != "" {
		canary = strings.Split(path, "/")[0]
		if !strings.HasSuffix(canary, ".oob.test") {
			canary += ".oob.test"
		}
	}
	s.mu.Lock()
	probeID := s.probes[canary]
	mismatch, delay := s.mismatch, s.delay
	s.mu.Unlock()
	if probeID == "" {
		return
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	if mismatch == "probe_id" {
		probeID = "wrong-probe-id"
	}
	protocol := "http"
	if mismatch == "protocol" {
		protocol = "dns"
	}
	s.mu.Lock()
	s.callback[probeID] = &oob.Interaction{ProbeID: probeID, Protocol: protocol, SourceIP: "127.0.0.1", At: time.Now().UTC()}
	s.mu.Unlock()
}

func randomToken() string {
	data := make([]byte, 8)
	_, _ = rand.Read(data)
	return hex.EncodeToString(data)
}

// CanaryURL converts an issued HTTP canary into a callback to this local fake.
// It is used only by the local fixture, never to expand target scope.
func (s *Server) CanaryURL(canary string) string {
	return s.server.URL + "/callback/" + url.PathEscape(strings.TrimSuffix(canary, ".oob.test"))
}

// ObserveCanary records a callback directly in the in-memory fake, avoiding
// any DNS dependency in tests. Wrong-ID/protocol modes remain testable.
func (s *Server) ObserveCanary(canary string) {
	req, _ := http.NewRequest(http.MethodGet, s.server.URL+"/callback/", nil)
	req.Host = canary
	s.observe(req)
}

func (s *Server) Client() oob.Client { return oob.NewHTTPPollingClient(s.server.URL) }
