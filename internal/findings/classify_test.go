package findings

import "testing"

func TestClassifyRequiresFullyCorrelatedOOBForConfirmation(t *testing.T) {
	if got := Classify(Evidence{CorrelatedOOB: true, ProtocolMatches: true, ProbeIDMatches: true}); got != Confirmed {
		t.Fatalf("got %s", got)
	}
	if got := Classify(Evidence{CorrelatedOOB: true, ProtocolMatches: false, ProbeIDMatches: true}); got == Confirmed {
		t.Fatal("mismatched protocol was confirmed")
	}
}
