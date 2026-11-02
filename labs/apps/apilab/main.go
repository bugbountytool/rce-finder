// Command apilab is a deliberately vulnerable REST API fixture for testing the
// API security engine. It is local-only and never exposed. It demonstrates
// BOLA (any principal can read any user), BFLA (admin function callable by a
// normal user), excessive data exposure (returns an undeclared ssn field), and
// mass assignment (accepts a read-only role on write).
package apilab

import (
	"encoding/json"
	"net/http"
	"strings"
)

type user struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
	SSN  string `json:"ssn"` // excessive exposure: not in the public schema
}

var users = map[string]user{
	"1": {ID: "1", Name: "alice", Role: "user", SSN: "111-11-1111"},
	"2": {ID: "2", Name: "bob", Role: "user", SSN: "222-22-2222"},
}

func principal(r *http.Request) string { return r.Header.Get("X-Lab-Principal") }

// Handler builds the vulnerable API's mux. Exposed for in-process lab tests.
func Handler() http.Handler {
	mux := http.NewServeMux()
	// BOLA: no ownership check — any principal reads any user object.
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		u, ok := users[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(u)
	})
	// Mass assignment: read-only role accepted on write.
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var in user
		_ = json.NewDecoder(r.Body).Decode(&in)
		users[in.ID] = in // role is stored verbatim -> mass assignment
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(in)
	})
	// BFLA: admin function without a role check.
	mux.HandleFunc("/admin/reset", func(w http.ResponseWriter, r *http.Request) {
		_ = principal(r) // principal is read but never authorized
		users = map[string]user{}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"reset":true}`))
	})
	return mux
}

