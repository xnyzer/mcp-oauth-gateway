package keys

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

const manifestName = "manifest.json"

// manifest is the on-disk key inventory, keys/manifest.json (SPEC §2.2).
// active_since drives the rotation-interval check (SPEC §2.3.1).
type manifest struct {
	Active      string             `json:"active"`
	ActiveSince time.Time          `json:"active_since"`
	Retiring    []manifestRetiring `json:"retiring"`
}

type manifestRetiring struct {
	Kid      string    `json:"kid"`
	NotAfter time.Time `json:"not_after"`
}

// retiredKey is a previously active key that still verifies outstanding
// tokens until NotAfter (SPEC §2.3.2).
type retiredKey struct {
	SigningKey
	NotAfter time.Time
}

// Config configures a Manager.
type Config struct {
	// Dir is the key directory (data/keys, created 0700).
	Dir string
	// Alg is the configured KEY_ALG; an active key of a different
	// algorithm triggers a rotation at startup (SPEC §3.2).
	Alg Alg
	// LegacyKeyPath, when it exists and no manifest does, is adopted as
	// the active key on first start (SPEC §2.2 migration). The file itself
	// is left untouched.
	LegacyKeyPath string
	// RotationInterval rotates the active key once its age exceeds it;
	// 0 disables automatic rotation (SPEC §2.3.1).
	RotationInterval time.Duration
	// RetireWindow is how long a rotated-out key keeps verifying:
	// ACCESS_TOKEN_TTL + 2×CLOCK_SKEW (SPEC §2.3.2).
	RetireWindow time.Duration
	Logger       *zap.Logger
}

// Manager owns the signing key set: one active key (signs all new tokens)
// plus retiring keys (verify-only). Safe for concurrent use; rotation and
// sweeping happen behind the same lock request handlers read through.
type Manager struct {
	mu       sync.RWMutex
	cfg      Config
	active   SigningKey
	since    time.Time
	retiring []retiredKey
	// static is the JWT_PRIVATE_KEY env mode: a single fixed key, no
	// directory, no rotation.
	static bool
}

// NewManager loads (or initializes) the key directory and runs the startup
// maintenance pass (rotation due / KEY_ALG switch / retiring sweep). It
// fails fast when the manifest references a missing or corrupt key file
// (SPEC §2.2).
func NewManager(cfg Config) (*Manager, error) {
	if _, err := ParseAlg(string(cfg.Alg)); err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	m := &Manager{cfg: cfg}
	now := time.Now().UTC()

	manifestPath := filepath.Join(cfg.Dir, manifestName)
	switch _, err := os.Stat(manifestPath); {
	case err == nil:
		if err := m.load(manifestPath, now); err != nil {
			return nil, err
		}
	case os.IsNotExist(err):
		if err := m.initialize(now); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("failed to stat key manifest: %w", err)
	}

	if err := m.Maintain(now); err != nil {
		return nil, err
	}
	return m, nil
}

// NewStaticManager wraps a single externally provided key (JWT_PRIVATE_KEY):
// no key directory, rotation disabled.
func NewStaticManager(key crypto.Signer, alg Alg) (*Manager, error) {
	keyAlg, err := algForKey(key)
	if err != nil {
		return nil, err
	}
	if keyAlg != alg {
		return nil, fmt.Errorf("KEY_ALG is %s but the provided private key requires %s", alg, keyAlg)
	}
	kid, err := KeyID(key.Public())
	if err != nil {
		return nil, err
	}
	return &Manager{
		cfg:    Config{Alg: alg, Logger: zap.NewNop()},
		active: SigningKey{Kid: kid, Alg: alg, Key: key},
		since:  time.Now().UTC(),
		static: true,
	}, nil
}

// load reads an existing manifest and every key it references (fail-fast on
// any missing/corrupt file or kid mismatch).
func (m *Manager) load(manifestPath string, now time.Time) error {
	mf, err := readManifest(manifestPath)
	if err != nil {
		return err
	}
	active, err := m.loadKey(mf.Active)
	if err != nil {
		return err
	}
	since := mf.ActiveSince
	if since.IsZero() {
		// Tolerate a hand-edited manifest: age the key from now on.
		since = now
	}
	retiring := make([]retiredKey, 0, len(mf.Retiring))
	for _, entry := range mf.Retiring {
		key, err := m.loadKey(entry.Kid)
		if err != nil {
			return err
		}
		retiring = append(retiring, retiredKey{SigningKey: key, NotAfter: entry.NotAfter})
	}
	m.active = active
	m.since = since
	m.retiring = retiring
	return nil
}

// initialize creates the first manifest: by adopting the legacy single-key
// file when present (SPEC §2.2 migration), otherwise with a fresh key.
func (m *Manager) initialize(now time.Time) error {
	if m.cfg.LegacyKeyPath != "" {
		if legacyPEM, err := os.ReadFile(m.cfg.LegacyKeyPath); err == nil {
			return m.adoptLegacyKey(legacyPEM, now)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read legacy key file: %w", err)
		}
	}
	key, err := GeneratePrivateKey(m.cfg.Alg)
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}
	kid, err := KeyID(key.Public())
	if err != nil {
		return err
	}
	if err := SavePrivateKey(m.keyPath(kid), key); err != nil {
		return fmt.Errorf("failed to save signing key: %w", err)
	}
	m.active = SigningKey{Kid: kid, Alg: m.cfg.Alg, Key: key}
	m.since = now
	m.cfg.Logger.Info("Generated new signing key", zap.String("kid", kid), zap.String("alg", string(m.cfg.Alg)))
	return m.writeManifest()
}

// adoptLegacyKey migrates the pre-F-005d single key file: it becomes the
// active key (keeping its kid, so outstanding tokens stay verifiable) and
// the original file is left in place.
func (m *Manager) adoptLegacyKey(legacyPEM []byte, now time.Time) error {
	key, err := ParsePrivateKeyPEM(string(legacyPEM))
	if err != nil {
		return fmt.Errorf("failed to parse legacy key file: %w", err)
	}
	alg, err := algForKey(key)
	if err != nil {
		return err
	}
	kid, err := KeyID(key.Public())
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.keyPath(kid), legacyPEM, 0600); err != nil {
		return fmt.Errorf("failed to adopt legacy key: %w", err)
	}
	m.active = SigningKey{Kid: kid, Alg: alg, Key: key}
	m.since = now
	m.cfg.Logger.Info("Adopted legacy signing key", zap.String("kid", kid), zap.String("alg", string(alg)))
	return m.writeManifest()
}

// loadKey reads and validates keys/<kid>.pem, verifying that the file's
// fingerprint matches the manifest kid.
func (m *Manager) loadKey(kid string) (SigningKey, error) {
	if kid == "" {
		return SigningKey{}, fmt.Errorf("key manifest contains an empty kid")
	}
	pemBytes, err := os.ReadFile(m.keyPath(kid))
	if err != nil {
		return SigningKey{}, fmt.Errorf("failed to read key %s referenced by the manifest: %w", kid, err)
	}
	key, err := ParsePrivateKeyPEM(string(pemBytes))
	if err != nil {
		return SigningKey{}, fmt.Errorf("failed to parse key %s: %w", kid, err)
	}
	alg, err := algForKey(key)
	if err != nil {
		return SigningKey{}, fmt.Errorf("key %s: %w", kid, err)
	}
	fingerprint, err := KeyID(key.Public())
	if err != nil {
		return SigningKey{}, err
	}
	if fingerprint != kid {
		return SigningKey{}, fmt.Errorf("key file %s does not match its manifest kid (fingerprint %s)", kid, fingerprint)
	}
	return SigningKey{Kid: kid, Alg: alg, Key: key}, nil
}

func (m *Manager) keyPath(kid string) string {
	return filepath.Join(m.cfg.Dir, kid+".pem")
}

// Active returns the key that signs new tokens.
func (m *Manager) Active() SigningKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// VerificationKey resolves a token's kid to a public key and its JWS alg;
// ok is false for unknown kids (SPEC §2.3.3: active + retiring only).
func (m *Manager) VerificationKey(kid string) (pub crypto.PublicKey, alg string, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if kid == "" {
		return nil, "", false
	}
	if kid == m.active.Kid {
		return m.active.Key.Public(), string(m.active.Alg), true
	}
	for _, retired := range m.retiring {
		if kid == retired.Kid {
			return retired.Key.Public(), string(retired.Alg), true
		}
	}
	return nil, "", false
}

// PublicJWKs returns the JWKS document key set: the active key first, then
// every retiring key (SPEC §1.8/§2.3.3).
func (m *Manager) PublicJWKs() ([]JWK, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := make([]JWK, 0, 1+len(m.retiring))
	jwk, err := publicJWK(m.active)
	if err != nil {
		return nil, err
	}
	set = append(set, jwk)
	for _, retired := range m.retiring {
		jwk, err := publicJWK(retired.SigningKey)
		if err != nil {
			return nil, err
		}
		set = append(set, jwk)
	}
	return set, nil
}

// Maintain runs one maintenance pass (SPEC §2.3): rotate when the interval
// has elapsed or KEY_ALG changed, then drop retiring keys past their
// not_after. Called at startup and periodically by the sweeper. A no-op in
// static (JWT_PRIVATE_KEY) mode.
func (m *Manager) Maintain(now time.Time) error {
	if m.static {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	rotationDue := m.cfg.RotationInterval > 0 && !now.Before(m.since.Add(m.cfg.RotationInterval))
	algSwitched := m.active.Alg != m.cfg.Alg
	if rotationDue || algSwitched {
		if algSwitched {
			m.cfg.Logger.Info("KEY_ALG changed, rotating signing key",
				zap.String("from", string(m.active.Alg)), zap.String("to", string(m.cfg.Alg)))
		}
		if err := m.rotateLocked(now); err != nil {
			return err
		}
	}
	return m.sweepLocked(now)
}

// Rotate forces a key rotation (used by tests; the interval-based trigger
// is Maintain).
func (m *Manager) Rotate(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rotateLocked(now)
}

// rotateLocked generates a new active key and moves the previous one to
// retiring (SPEC §2.3.2). Write order is crash-safe: the new key file
// first, the manifest last (atomic rename) — a crash in between leaves the
// old manifest fully intact (§2.3.5). In-memory state changes only after
// the manifest is durable.
func (m *Manager) rotateLocked(now time.Time) error {
	if m.static {
		return fmt.Errorf("key rotation is not available with an externally provided key (JWT_PRIVATE_KEY)")
	}
	key, err := GeneratePrivateKey(m.cfg.Alg)
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}
	kid, err := KeyID(key.Public())
	if err != nil {
		return err
	}
	if err := SavePrivateKey(m.keyPath(kid), key); err != nil {
		return fmt.Errorf("failed to save signing key: %w", err)
	}

	previousActive := m.active
	previousSince := m.since
	previousRetiring := m.retiring

	m.active = SigningKey{Kid: kid, Alg: m.cfg.Alg, Key: key}
	m.since = now
	m.retiring = append(append([]retiredKey{}, previousRetiring...), retiredKey{
		SigningKey: previousActive,
		NotAfter:   now.Add(m.cfg.RetireWindow),
	})
	if err := m.writeManifest(); err != nil {
		m.active = previousActive
		m.since = previousSince
		m.retiring = previousRetiring
		return err
	}
	m.cfg.Logger.Info("Rotated signing key",
		zap.String("kid", kid),
		zap.String("alg", string(m.cfg.Alg)),
		zap.String("retiring_kid", previousActive.Kid),
		zap.Time("retiring_not_after", now.Add(m.cfg.RetireWindow)))
	return nil
}

// sweepLocked removes retiring keys past their not_after (SPEC §2.3.4).
// The manifest is rewritten before the key files are deleted, so a crash
// in between leaves only an orphaned file, never a manifest referencing a
// missing key.
func (m *Manager) sweepLocked(now time.Time) error {
	kept := make([]retiredKey, 0, len(m.retiring))
	var expired []retiredKey
	for _, retired := range m.retiring {
		if now.Before(retired.NotAfter) {
			kept = append(kept, retired)
		} else {
			expired = append(expired, retired)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	previousRetiring := m.retiring
	m.retiring = kept
	if err := m.writeManifest(); err != nil {
		m.retiring = previousRetiring
		return err
	}
	for _, retired := range expired {
		if err := os.Remove(m.keyPath(retired.Kid)); err != nil && !os.IsNotExist(err) {
			m.cfg.Logger.Warn("Failed to delete retired key file", zap.String("kid", retired.Kid), zap.Error(err))
		}
		m.cfg.Logger.Info("Removed retired signing key", zap.String("kid", retired.Kid))
	}
	return nil
}
