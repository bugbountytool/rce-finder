package apisec

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/model"
	"github.com/bugbountytool/rce-finder/internal/verify"
)

func usersOp() Operation {
	return Operation{
		Method: "GET", Path: "/users/123", RequiresAuth: true,
		ResponseProperties: []SchemaProperty{{Name: "id"}, {Name: "name"}},
	}
}

func TestExcessiveDataExposure(t *testing.T) {
	resp := Response{StatusCode: 200, Body: []byte(`{"id":1,"name":"a","ssn":"123-45-6789"}`)}
	fs := DetectExcessiveDataExposure(usersOp(), resp)
	if len(fs) != 1 || fs[0].Property != "ssn" {
		t.Fatalf("exposure findings = %+v", fs)
	}
	// conformant response -> no finding
	resp.Body = []byte(`{"id":1,"name":"a"}`)
	if fs := DetectExcessiveDataExposure(usersOp(), resp); len(fs) != 0 {
		t.Fatalf("false positive on conformant response: %+v", fs)
	}
}

func TestMassAssignment(t *testing.T) {
	op := Operation{Method: "POST", Path: "/users", WritableProperties: []SchemaProperty{
		{Name: "name"}, {Name: "role", ReadOnly: true},
	}}
	if fs := DetectMassAssignment(op, "role", true); len(fs) != 1 || fs[0].CWE != "CWE-915" {
		t.Fatalf("mass assignment not detected: %+v", fs)
	}
	if fs := DetectMassAssignment(op, "name", true); len(fs) != 0 {
		t.Fatal("writable property falsely flagged")
	}
	if fs := DetectMassAssignment(op, "role", false); len(fs) != 0 {
		t.Fatal("rejected write falsely flagged")
	}
}

func TestBOLADifferential(t *testing.T) {
	owner := Response{StatusCode: 200, Body: []byte(`{"id":1,"name":"alice"}`), Principal: "alice"}
	other := Response{StatusCode: 200, Body: []byte(`{"id":1,"name":"alice"}`), Principal: "bob"}
	fs := DetectBOLA(usersOp(), owner, other, true)
	if len(fs) != 1 || !fs[0].Differential || fs[0].CWE != "CWE-639" {
		t.Fatalf("BOLA not detected: %+v", fs)
	}
	// denied for non-owner -> no finding
	otherDenied := Response{StatusCode: 403, Principal: "bob"}
	if fs := DetectBOLA(usersOp(), owner, otherDenied, true); len(fs) != 0 {
		t.Fatal("denied access falsely flagged as BOLA")
	}
	// owner also failed -> inconclusive, not BOLA
	ownerFail := Response{StatusCode: 500}
	if fs := DetectBOLA(usersOp(), ownerFail, other, true); len(fs) != 0 {
		t.Fatal("inconclusive owner read falsely flagged")
	}
}

func TestBFLA(t *testing.T) {
	op := Operation{Method: "DELETE", Path: "/admin/users/1", AdminOnly: true}
	admin := Response{StatusCode: 200, Principal: "admin"}
	user := Response{StatusCode: 200, Principal: "user"}
	fs := DetectBFLA(op, admin, user, true)
	if len(fs) != 1 || fs[0].CWE != "CWE-862" {
		t.Fatalf("BFLA not detected: %+v", fs)
	}
	userDenied := Response{StatusCode: 403, Principal: "user"}
	if fs := DetectBFLA(op, admin, userDenied, true); len(fs) != 0 {
		t.Fatal("denied admin function falsely flagged")
	}
}

func TestReproducedBOLABecomesHighConfidence(t *testing.T) {
	owner := Response{StatusCode: 200, Body: []byte(`{"id":1}`)}
	other := Response{StatusCode: 200, Body: []byte(`{"id":1}`), Principal: "bob"}
	fs := DetectBOLA(usersOp(), owner, other, true)
	cand := fs[0].ToCandidate("https://api.example.test")
	f, err := verify.New().Verify(cand, []verify.Observation{fs[0].ToObservation()})
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != model.StatusHighConfidence {
		t.Fatalf("reproduced BOLA = %s, want HIGH_CONFIDENCE", f.Status)
	}
	// Unreproduced BOLA must stay POTENTIAL.
	fs2 := DetectBOLA(usersOp(), owner, other, false)
	f2, _ := verify.New().Verify(fs2[0].ToCandidate("https://api.example.test"), []verify.Observation{fs2[0].ToObservation()})
	if f2.Status == model.StatusHighConfidence || f2.Status == model.StatusConfirmed {
		t.Fatalf("unreproduced BOLA = %s, want POTENTIAL", f2.Status)
	}
}

func TestNegativeDataRejection(t *testing.T) {
	resp := Response{StatusCode: 200}
	if fs := DetectNegativeDataRejection(usersOp(), resp); len(fs) != 1 {
		t.Fatal("accepted invalid input not flagged")
	}
	resp.StatusCode = 400
	if fs := DetectNegativeDataRejection(usersOp(), resp); len(fs) != 0 {
		t.Fatal("proper rejection falsely flagged")
	}
}
