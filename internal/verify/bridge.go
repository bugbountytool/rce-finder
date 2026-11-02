package verify

import (
	"github.com/bugbountytool/rce-finder/internal/model"
)

// ObservationsFromStatus maps an already-classified engine status back to the
// observation that would produce it. This lets the kernel re-derive and audit
// an engine result, proving the engine's classification matches the rule table.
// It is used by the consistency test, not by the live scan path.
func ObservationsFromStatus(status model.Status, probeIDMatch, protocolMatch bool) []Observation {
	switch status {
	case model.StatusConfirmed:
		return []Observation{{Kind: ObsOOBCorrelated, ProbeIDMatches: probeIDMatch, ProtocolMatches: protocolMatch}}
	case model.StatusHighConfidence:
		return []Observation{{Kind: ObsDifferential, Repeated: true, ControlMatched: true}}
	case model.StatusPotential:
		return []Observation{{Kind: ObsErrorSig}}
	case model.StatusNotVulnerable:
		return []Observation{{Kind: ObsNegative}}
	case model.StatusBlocked:
		return []Observation{{Kind: ObsBlocked}}
	case model.StatusError:
		return []Observation{{Kind: ObsError}}
	case model.StatusInconclusive:
		return []Observation{{Kind: ObsFingerprint}}
	default:
		return nil
	}
}
