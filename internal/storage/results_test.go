package storage

import (
	"path/filepath"
	"testing"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

func TestWriteAndReadSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "scan.json")
	results := []engine.Result{{ProbeID: "p1", Status: engine.StatusConfirmed}}
	if err := WriteSnapshot(path, results); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSnapshot(path)
	if err != nil || len(got.Results) != 1 || got.Results[0].ProbeID != "p1" {
		t.Fatalf("ReadSnapshot() = %#v, %v", got, err)
	}
	if err := WriteSnapshot(path, results); err == nil {
		t.Fatal("WriteSnapshot overwrote existing file")
	}
}
