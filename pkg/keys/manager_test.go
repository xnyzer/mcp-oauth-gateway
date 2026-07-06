package keys

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	if cfg.Dir == "" {
		cfg.Dir = filepath.Join(t.TempDir(), "keys")
	}
	if cfg.Alg == "" {
		cfg.Alg = AlgRS256
	}
	if cfg.RetireWindow == 0 {
		cfg.RetireWindow = time.Hour
	}
	m, err := NewManager(cfg)
	require.NoError(t, err)
	return m
}

func readManifestFile(t *testing.T, dir string) manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	require.NoError(t, err)
	var mf manifest
	require.NoError(t, json.Unmarshal(data, &mf))
	return mf
}

func TestNewManager_GeneratesKeyAndManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir})

	active := m.Active()
	require.NotEmpty(t, active.Kid)
	require.Equal(t, AlgRS256, active.Alg)
	require.IsType(t, &rsa.PrivateKey{}, active.Key)

	// The kid is the fingerprint of the public key (existing scheme).
	fingerprint, err := KeyID(active.Key.Public())
	require.NoError(t, err)
	require.Equal(t, fingerprint, active.Kid)

	// Manifest and key file exist with restrictive permissions (SPEC §2.2).
	mf := readManifestFile(t, dir)
	require.Equal(t, active.Kid, mf.Active)
	require.False(t, mf.ActiveSince.IsZero())
	require.Empty(t, mf.Retiring)

	keyInfo, err := os.Stat(filepath.Join(dir, active.Kid+".pem"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm())
	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())

	// A second start loads the same key.
	m2 := newTestManager(t, Config{Dir: dir})
	require.Equal(t, active.Kid, m2.Active().Kid)
}

func TestNewManager_GeneratesES256Key(t *testing.T) {
	m := newTestManager(t, Config{Alg: AlgES256})
	active := m.Active()
	require.Equal(t, AlgES256, active.Alg)
	require.IsType(t, &ecdsa.PrivateKey{}, active.Key)

	jwks, err := m.PublicJWKs()
	require.NoError(t, err)
	require.Len(t, jwks, 1)
	require.Equal(t, "EC", jwks[0].Kty)
	require.Equal(t, "P-256", jwks[0].Crv)
	require.NotEmpty(t, jwks[0].X)
	require.NotEmpty(t, jwks[0].Y)
}

func TestNewManager_AdoptsLegacyKey(t *testing.T) {
	// Legacy layout: a single data/private_key.pem as written by the
	// pre-F-005d LoadOrGeneratePrivateKey.
	dataDir := t.TempDir()
	legacyPath := filepath.Join(dataDir, "private_key.pem")
	legacyKey, err := GeneratePrivateKey(AlgRS256)
	require.NoError(t, err)
	require.NoError(t, SavePrivateKey(legacyPath, legacyKey))
	legacyKid, err := KeyID(legacyKey.Public())
	require.NoError(t, err)

	dir := filepath.Join(dataDir, "keys")
	m := newTestManager(t, Config{Dir: dir, LegacyKeyPath: legacyPath})

	// The legacy key is the active key and keeps its kid, so outstanding
	// tokens signed by it stay verifiable across the upgrade.
	require.Equal(t, legacyKid, m.Active().Kid)
	pub, alg, ok := m.VerificationKey(legacyKid)
	require.True(t, ok)
	require.Equal(t, "RS256", alg)
	require.True(t, legacyKey.Public().(*rsa.PublicKey).Equal(pub.(*rsa.PublicKey)))

	// The original file is left in place; the key dir has its own copy.
	require.FileExists(t, legacyPath)
	require.FileExists(t, filepath.Join(dir, legacyKid+".pem"))

	// A restart loads via the manifest, not the legacy path.
	m2 := newTestManager(t, Config{Dir: dir})
	require.Equal(t, legacyKid, m2.Active().Kid)
}

func TestNewManager_FailsOnManifestReferencingMissingKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir})
	require.NoError(t, os.Remove(filepath.Join(dir, m.Active().Kid+".pem")))

	_, err := NewManager(Config{Dir: dir, Alg: AlgRS256, RetireWindow: time.Hour})
	require.Error(t, err)
	require.Contains(t, err.Error(), "referenced by the manifest")
}

func TestNewManager_FailsOnKidMismatch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir})

	// Swap the key file for a different key: fingerprint no longer
	// matches the manifest kid.
	otherKey, err := GeneratePrivateKey(AlgRS256)
	require.NoError(t, err)
	require.NoError(t, SavePrivateKey(filepath.Join(dir, m.Active().Kid+".pem"), otherKey))

	_, err = NewManager(Config{Dir: dir, Alg: AlgRS256, RetireWindow: time.Hour})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match its manifest kid")
}

func TestRotate_MovesActiveToRetiring(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir, RetireWindow: time.Hour})
	oldActive := m.Active()

	now := time.Now().UTC()
	require.NoError(t, m.Rotate(now))

	newActive := m.Active()
	require.NotEqual(t, oldActive.Kid, newActive.Kid)

	// Both keys verify; JWKS serves active first, then retiring (§1.8).
	_, _, ok := m.VerificationKey(newActive.Kid)
	require.True(t, ok)
	_, _, ok = m.VerificationKey(oldActive.Kid)
	require.True(t, ok)
	jwks, err := m.PublicJWKs()
	require.NoError(t, err)
	require.Len(t, jwks, 2)
	require.Equal(t, newActive.Kid, jwks[0].Kid)
	require.Equal(t, oldActive.Kid, jwks[1].Kid)

	// The manifest reflects the rotation with the retire window (§2.3.2).
	mf := readManifestFile(t, dir)
	require.Equal(t, newActive.Kid, mf.Active)
	require.Len(t, mf.Retiring, 1)
	require.Equal(t, oldActive.Kid, mf.Retiring[0].Kid)
	require.WithinDuration(t, now.Add(time.Hour), mf.Retiring[0].NotAfter, time.Second)

	// A restart restores the full key set.
	m2 := newTestManager(t, Config{Dir: dir})
	_, _, ok = m2.VerificationKey(oldActive.Kid)
	require.True(t, ok)
	require.Equal(t, newActive.Kid, m2.Active().Kid)
}

func TestMaintain_RotatesOnceIntervalElapsed(t *testing.T) {
	m := newTestManager(t, Config{RotationInterval: 24 * time.Hour})
	oldKid := m.Active().Kid

	// Not yet due.
	require.NoError(t, m.Maintain(time.Now().UTC().Add(23*time.Hour)))
	require.Equal(t, oldKid, m.Active().Kid)

	// Due.
	require.NoError(t, m.Maintain(time.Now().UTC().Add(25*time.Hour)))
	require.NotEqual(t, oldKid, m.Active().Kid)
	_, _, ok := m.VerificationKey(oldKid)
	require.True(t, ok, "rotated-out key must keep verifying")
}

func TestMaintain_ZeroIntervalNeverRotates(t *testing.T) {
	m := newTestManager(t, Config{})
	kid := m.Active().Kid
	require.NoError(t, m.Maintain(time.Now().UTC().Add(10*365*24*time.Hour)))
	require.Equal(t, kid, m.Active().Kid)
}

func TestNewManager_AlgSwitchTriggersRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir, Alg: AlgRS256})
	rsaKid := m.Active().Kid

	// Restart with KEY_ALG=ES256: rotation at startup (SPEC §3.2), the
	// RSA key retires but keeps verifying outstanding tokens.
	m2 := newTestManager(t, Config{Dir: dir, Alg: AlgES256})
	active := m2.Active()
	require.Equal(t, AlgES256, active.Alg)
	require.NotEqual(t, rsaKid, active.Kid)

	_, alg, ok := m2.VerificationKey(rsaKid)
	require.True(t, ok)
	require.Equal(t, "RS256", alg)

	jwks, err := m2.PublicJWKs()
	require.NoError(t, err)
	require.Len(t, jwks, 2)
	require.Equal(t, "EC", jwks[0].Kty)
	require.Equal(t, "RSA", jwks[1].Kty)
}

func TestMaintain_SweepsRetiredKeysPastNotAfter(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir, RetireWindow: time.Hour})
	oldKid := m.Active().Kid

	now := time.Now().UTC()
	require.NoError(t, m.Rotate(now))

	// Within the retire window the key stays.
	require.NoError(t, m.Maintain(now.Add(30*time.Minute)))
	_, _, ok := m.VerificationKey(oldKid)
	require.True(t, ok)

	// Past not_after it is dropped from manifest, memory, and disk.
	require.NoError(t, m.Maintain(now.Add(2*time.Hour)))
	_, _, ok = m.VerificationKey(oldKid)
	require.False(t, ok)
	require.NoFileExists(t, filepath.Join(dir, oldKid+".pem"))
	mf := readManifestFile(t, dir)
	require.Empty(t, mf.Retiring)
	jwks, err := m.PublicJWKs()
	require.NoError(t, err)
	require.Len(t, jwks, 1)
}

func TestRotate_FailureLeavesManifestIntact(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir})
	oldKid := m.Active().Kid

	// Make the directory unwritable so the rotation cannot persist.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	err := m.Rotate(time.Now().UTC())
	require.Error(t, err)

	// In-memory state and on-disk manifest still describe the old key.
	require.Equal(t, oldKid, m.Active().Kid)
	require.NoError(t, os.Chmod(dir, 0700))
	mf := readManifestFile(t, dir)
	require.Equal(t, oldKid, mf.Active)
	require.Empty(t, mf.Retiring)

	m2 := newTestManager(t, Config{Dir: dir})
	require.Equal(t, oldKid, m2.Active().Kid)
}

func TestNewStaticManager(t *testing.T) {
	key, err := GeneratePrivateKey(AlgRS256)
	require.NoError(t, err)

	// Alg mismatch fails fast.
	_, err = NewStaticManager(key, AlgES256)
	require.Error(t, err)
	require.Contains(t, err.Error(), "KEY_ALG")

	m, err := NewStaticManager(key, AlgRS256)
	require.NoError(t, err)
	kid := m.Active().Kid
	_, _, ok := m.VerificationKey(kid)
	require.True(t, ok)

	// Maintenance is a no-op, explicit rotation is refused.
	require.NoError(t, m.Maintain(time.Now().UTC().Add(10*365*24*time.Hour)))
	require.Equal(t, kid, m.Active().Kid)
	require.Error(t, m.Rotate(time.Now().UTC()))
}

func TestParseAlg(t *testing.T) {
	alg, err := ParseAlg("rs256")
	require.NoError(t, err)
	require.Equal(t, AlgRS256, alg)
	alg, err = ParseAlg("ES256")
	require.NoError(t, err)
	require.Equal(t, AlgES256, alg)
	_, err = ParseAlg("HS256")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported key algorithm")
}

func TestParsePrivateKeyPEM_RejectsUnsupportedCurve(t *testing.T) {
	_, err := ParsePrivateKeyPEM("not a pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestVerificationKey_UnknownAndEmptyKid(t *testing.T) {
	m := newTestManager(t, Config{})
	_, _, ok := m.VerificationKey("")
	require.False(t, ok)
	_, _, ok = m.VerificationKey("nope")
	require.False(t, ok)
}
