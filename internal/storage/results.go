// Package storage provides local, atomic persistence for scan artifacts.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bugbountytool/rce-finder/internal/engine"
)

// Snapshot is a portable, append-free record of one completed scan run.
type Snapshot struct {
	Version             string          `json:"version"`
	CreatedAt           time.Time       `json:"created_at"`
	ScanID              string          `json:"scan_id,omitempty"`
	ScopeFingerprint    string          `json:"scope_fingerprint,omitempty"`
	TemplateFingerprint string          `json:"template_fingerprint,omitempty"`
	PolicyFingerprint   string          `json:"policy_fingerprint,omitempty"`
	CompletedJobIDs     []string        `json:"completed_job_ids,omitempty"`
	Results             []engine.Result `json:"results"`
}

// WriteSnapshot writes a new file atomically and refuses to overwrite an
// existing result, preserving auditability.
func WriteSnapshot(path string, results []engine.Result) error {
	return WriteJobSnapshot(path, Snapshot{Results: results})
}

// WriteJobSnapshot atomically persists scan state without any request secrets.
func WriteJobSnapshot(path string, snapshot Snapshot) error {
	if path == "" {
		return fmt.Errorf("snapshot path is required")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("snapshot %s already exists", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeAtomic(path, snapshot, true)
}

// UpdateJobSnapshot replaces only a snapshot previously created by this run.
// The temporary file plus rename keeps cancellation from exposing partial JSON.
func UpdateJobSnapshot(path string, snapshot Snapshot) error {
	if path == "" {
		return fmt.Errorf("snapshot path is required")
	}
	if _, err := ReadSnapshot(path); err != nil {
		return fmt.Errorf("updating snapshot: %w", err)
	}
	return writeAtomic(path, snapshot, false)
}

func writeAtomic(path string, snapshot Snapshot, exclusive bool) error {
	snapshot.Version = "rce-finder/results-v1"
	snapshot.CreatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding snapshot: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".rce-finder-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if exclusive {
		if err := os.Link(tmpName, path); err != nil {
			return fmt.Errorf("committing snapshot: %w", err)
		}
		return nil
	}
	return os.Rename(tmpName, path)
}

func ReadSnapshot(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decoding snapshot: %w", err)
	}
	if snapshot.Version != "rce-finder/results-v1" {
		return Snapshot{}, fmt.Errorf("unsupported snapshot version %q", snapshot.Version)
	}
	return snapshot, nil
}
