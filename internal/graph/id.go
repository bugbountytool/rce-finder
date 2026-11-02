package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// NodeID derives a stable, deterministic identifier from kind, name and the
// sorted attributes, so the same logical node deduplicates across runs.
func NodeID(kind NodeKind, name string, attrs map[string]string) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(name))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k + "=" + attrs[k]))
	}
	return string(kind) + ":" + hex.EncodeToString(h.Sum(nil)[:12])
}

// CanonicalJSON renders a node deterministically for hashing and export.
func (n Node) CanonicalJSON() string {
	keys := make([]string, 0, len(n.Attrs))
	for k := range n.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m := map[string]any{"id": n.ID, "kind": n.Kind, "name": n.Name}
	sorted := map[string]string{}
	for _, k := range keys {
		sorted[k] = n.Attrs[k]
	}
	m["attrs"] = sorted
	b, _ := json.Marshal(m)
	return string(b)
}
