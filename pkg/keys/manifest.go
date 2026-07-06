package keys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func readManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key manifest: %w", err)
	}
	var mf manifest
	if err := json.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("failed to parse key manifest: %w", err)
	}
	return &mf, nil
}

// writeManifest persists the current key inventory atomically: write to a
// temp file, fsync, rename (SPEC §2.2/§2.3.5 — a crash mid-write leaves the
// previous manifest intact). Callers hold m.mu.
func (m *Manager) writeManifest() error {
	mf := manifest{
		Active:      m.active.Kid,
		ActiveSince: m.since,
		Retiring:    make([]manifestRetiring, 0, len(m.retiring)),
	}
	for _, retired := range m.retiring {
		mf.Retiring = append(mf.Retiring, manifestRetiring{Kid: retired.Kid, NotAfter: retired.NotAfter})
	}
	data, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key manifest: %w", err)
	}

	manifestPath := filepath.Join(m.cfg.Dir, manifestName)
	tmpPath := manifestPath + ".tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary key manifest: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write key manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync key manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close key manifest: %w", err)
	}
	if err := os.Rename(tmpPath, manifestPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace key manifest: %w", err)
	}
	return nil
}
