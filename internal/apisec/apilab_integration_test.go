//go:build integration

package apisec_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/apisec"
	"github.com/bugbountytool/rce-finder/labs/apps/apilab"
)

func do(t *testing.T, srv *httptest.Server, method, path, principal string, body []byte) apisec.Response {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	req.Header.Set("X-Lab-Principal", principal)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return apisec.Response{StatusCode: resp.StatusCode, Body: b, Principal: principal}
}

// Drives the vulnerable API lab and asserts each weakness is detected.
func TestAPILabDetections(t *testing.T) {
	srv := httptest.NewServer(apilab.Handler())
	defer srv.Close()

	// Excessive data exposure: /users/1 returns an undeclared ssn.
	op := apisec.Operation{Method: "GET", Path: "/users/1",
		ResponseProperties: []apisec.SchemaProperty{{Name: "id"}, {Name: "name"}, {Name: "role"}}}
	resp := do(t, srv, "GET", "/users/1", "alice", nil)
	exposure := apisec.DetectExcessiveDataExposure(op, resp)
	if len(exposure) == 0 {
		t.Fatal("excessive data exposure (ssn) not detected")
	}

	// BOLA: bob reads alice's object and gets the same data.
	owner := do(t, srv, "GET", "/users/1", "alice", nil)
	other := do(t, srv, "GET", "/users/1", "bob", nil)
	bola := apisec.DetectBOLA(op, owner, other, true)
	if len(bola) != 1 {
		t.Fatalf("BOLA not detected against lab: %+v", bola)
	}

	// BFLA: a normal user invokes the admin reset function.
	adminOp := apisec.Operation{Method: "POST", Path: "/admin/reset", AdminOnly: true}
	admin := do(t, srv, "POST", "/admin/reset", "admin", nil)
	user := do(t, srv, "POST", "/admin/reset", "user", nil)
	bfla := apisec.DetectBFLA(adminOp, admin, user, true)
	if len(bfla) != 1 {
		t.Fatalf("BFLA not detected against lab: %+v", bfla)
	}

	// Mass assignment: read-only role accepted on write.
	body, _ := json.Marshal(map[string]string{"id": "9", "name": "x", "role": "admin"})
	wr := do(t, srv, "POST", "/users", "alice", body)
	writeOp := apisec.Operation{Method: "POST", Path: "/users", WritableProperties: []apisec.SchemaProperty{
		{Name: "id"}, {Name: "name"}, {Name: "role", ReadOnly: true},
	}}
	accepted := wr.StatusCode == 201
	ma := apisec.DetectMassAssignment(writeOp, "role", accepted)
	if len(ma) != 1 {
		t.Fatalf("mass assignment not detected against lab (status=%d)", wr.StatusCode)
	}
}
