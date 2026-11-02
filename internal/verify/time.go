package verify

import (
	"time"

	"github.com/bugbountytool/rce-finder/internal/model"
)

// nowUTC is a seam for deterministic tests.
var nowUTC = func() time.Time { return time.Now().UTC() }

// ForbiddenTransitions documents and enforces the rule that certain evidence
// kinds can never reach CONFIRMED, regardless of combination.
var _ = model.StatusConfirmed
