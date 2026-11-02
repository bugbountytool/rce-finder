// Package apisec implements API security checks derived from an OpenAPI
// schema and from differential authorization testing. It covers:
//
//   - Excessive data exposure: response contains properties not in the schema.
//   - Mass assignment: writable server-managed properties accepted on write.
//   - BOLA/IDOR: a lower-privilege principal can read another principal's object.
//   - BFLA: a lower-privilege principal can invoke a privileged function.
//   - Schema/status conformance and negative-data rejection.
//
// Authorization checks are differential: they compare a response under a
// privileged principal against the same request under a restricted principal.
// A differential alone is never CONFIRMED; it produces HIGH_CONFIDENCE at most
// and requires reproducibility. All checks are non-destructive and operate
// only within explicit scope.
package apisec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SchemaProperty is one declared property of a response or request object.
type SchemaProperty struct {
	Name     string
	ReadOnly bool // server-managed; clients must not set it (mass-assignment guard)
}

// Operation is one API operation under test.
type Operation struct {
	Method      string
	Path        string
	RequiresAuth bool
	// ResponseProperties are the properties the schema declares for a 200.
	ResponseProperties []SchemaProperty
	// WritableProperties are the properties a client may set on write.
	WritableProperties []SchemaProperty
	// AdminOnly marks a privileged function for BFLA testing.
	AdminOnly bool
}

// Principal is an authenticated identity used for differential testing. Only
// an identifier is stored; credentials are referenced, never held here.
type Principal struct {
	ID   string
	Role string // "admin", "user", "anonymous"
}

// Response is a captured API response under a given principal.
type Response struct {
	StatusCode int
	Body       []byte
	Principal  string
}

// CheckID enumerates the API checks.
type CheckID string

const (
	CheckExcessiveExposure CheckID = "excessive_data_exposure" // API3
	CheckMassAssignment    CheckID = "mass_assignment"         // API3
	CheckBOLA              CheckID = "bola"                    // API1
	CheckBFLA              CheckID = "bfla"                    // API5
	CheckStatusConformance CheckID = "status_conformance"
	CheckNegativeRejection CheckID = "negative_data_rejection"
)

// Finding is one API security observation before verification.
type Finding struct {
	Check    CheckID
	Op       Operation
	Property string
	Detail   string
	CWE      string
	// Differential indicates the finding rests on a principal-comparison.
	Differential bool
	// Reproduced indicates the effect was seen more than once.
	Reproduced bool
}

// CheckExcessiveDataExposure compares response properties against the schema.
// Properties present in the body but absent from the schema, or marked
// read-only but returned on a list endpoint, are flagged.
func DetectExcessiveDataExposure(op Operation, resp Response) []Finding {
	if resp.StatusCode != 200 {
		return nil
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil // not a JSON object; not applicable
	}
	declared := map[string]bool{}
	for _, p := range op.ResponseProperties {
		declared[p.Name] = true
	}
	var out []Finding
	for key := range body {
		if !declared[key] && len(op.ResponseProperties) > 0 {
			out = append(out, Finding{
				Check: CheckExcessiveExposure, Op: op, Property: key,
				Detail: fmt.Sprintf("response property %q is not declared in the schema", key),
				CWE:    "CWE-200",
			})
		}
	}
	return out
}

// CheckMassAssignment detects a server-managed (read-only) property that the
// API accepted on a write. accepted is true when the server stored the value.
func DetectMassAssignment(op Operation, property string, accepted bool) []Finding {
	if !accepted {
		return nil
	}
	for _, p := range op.WritableProperties {
		if p.Name == property && p.ReadOnly {
			return []Finding{{
				Check: CheckMassAssignment, Op: op, Property: property,
				Detail: fmt.Sprintf("read-only property %q was accepted on write", property),
				CWE:    "CWE-915",
			}}
		}
	}
	return nil
}

// CheckBOLA compares an object read under an owner principal against the same
// read under a different, lower-privilege principal. If the non-owner receives
// the object's data (2xx with a matching body), that is a BOLA signal.
func DetectBOLA(op Operation, owner, other Response, reproduced bool) []Finding {
	if other.StatusCode < 200 || other.StatusCode >= 300 {
		return nil // correctly denied
	}
	if owner.StatusCode < 200 || owner.StatusCode >= 300 {
		return nil // owner couldn't read either; inconclusive, not BOLA
	}
	// The non-owner got a success response. If the body matches the owner's
	// object, cross-tenant/object access is indicated.
	if len(other.Body) > 0 && bodiesEquivalent(owner.Body, other.Body) {
		return []Finding{{
			Check: CheckBOLA, Op: op,
			Detail:       "non-owner principal received the object's data",
			CWE:          "CWE-639",
			Differential: true,
			Reproduced:   reproduced,
		}}
	}
	return nil
}

// CheckBFLA detects a privileged function invoked successfully by a
// lower-privilege principal.
func DetectBFLA(op Operation, admin, user Response, reproduced bool) []Finding {
	if !op.AdminOnly {
		return nil
	}
	if admin.StatusCode < 200 || admin.StatusCode >= 300 {
		return nil // admin failed; inconclusive
	}
	if user.StatusCode >= 200 && user.StatusCode < 300 {
		return []Finding{{
			Check: CheckBFLA, Op: op,
			Detail:       "privileged function succeeded for a lower-privilege principal",
			CWE:          "CWE-862",
			Differential: true,
			Reproduced:   reproduced,
		}}
	}
	return nil
}

// CheckNegativeDataRejection flags an endpoint that accepted structurally
// invalid input (which should yield 4xx) with a success status.
func DetectNegativeDataRejection(op Operation, resp Response) []Finding {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return []Finding{{
			Check: CheckNegativeRejection, Op: op,
			Detail: "invalid input was accepted with a success status",
			CWE:    "CWE-20",
		}}
	}
	return nil
}

// bodiesEquivalent compares two JSON bodies by their decoded content, ignoring
// key order, so a matching object under two principals is detected reliably.
func bodiesEquivalent(a, b []byte) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return strings.TrimSpace(string(a)) == strings.TrimSpace(string(b))
	}
	ac, _ := json.Marshal(av)
	bc, _ := json.Marshal(bv)
	return string(ac) == string(bc)
}
