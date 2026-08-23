package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRotateKeyCommand covers the manual key-rotation ops command
// (SPEC §2.3): each run makes a fresh key active and moves the previous
// active key into the retiring set (kid continuity).
func TestRotateKeyCommand(t *testing.T) {
	dataPath := t.TempDir()

	type manifest struct {
		Active   string `json:"active"`
		Retiring []struct {
			Kid string `json:"kid"`
		} `json:"retiring"`
	}
	readManifest := func(t *testing.T) manifest {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dataPath, "keys", "manifest.json"))
		require.NoError(t, err)
		var mf manifest
		require.NoError(t, json.Unmarshal(data, &mf))
		return mf
	}
	runRotate := func(t *testing.T) string {
		t.Helper()
		var out bytes.Buffer
		cmd := newRootCommand(nil)
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"rotate-key", "--data-path", dataPath})
		require.NoError(t, cmd.Execute())
		return out.String()
	}

	output := runRotate(t)
	require.Contains(t, output, "Rotated signing key")
	require.Contains(t, output, "Restart the gateway")

	first := readManifest(t)
	require.NotEmpty(t, first.Active)
	require.Len(t, first.Retiring, 1, "the initial key must retire, not disappear")

	runRotate(t)
	second := readManifest(t)
	require.NotEqual(t, first.Active, second.Active, "each rotation must mint a fresh active key")
	retiringKids := make([]string, 0, len(second.Retiring))
	for _, r := range second.Retiring {
		retiringKids = append(retiringKids, r.Kid)
	}
	require.Contains(t, retiringKids, first.Active,
		"the previously active kid must stay verifiable (retiring)")
}

func TestRotateKeyCommand_RejectsStaticKeyMode(t *testing.T) {
	t.Setenv("JWT_PRIVATE_KEY", "irrelevant")
	cmd := newRootCommand(nil)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"rotate-key", "--data-path", t.TempDir()})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT_PRIVATE_KEY")
}

func TestRotateKeyCommand_ValidatesFlags(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		errContains string
	}{
		{name: "unsupported algorithm", args: []string{"--key-alg", "HS256"}, errContains: "unsupported key algorithm"},
		{name: "access token TTL out of range", args: []string{"--access-token-ttl", "10s"}, errContains: "access token TTL"},
		{name: "clock skew out of range", args: []string{"--clock-skew", "10m"}, errContains: "clock skew"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCommand(nil)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append([]string{"rotate-key", "--data-path", t.TempDir()}, tt.args...))
			err := cmd.Execute()
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errContains)
		})
	}
}
