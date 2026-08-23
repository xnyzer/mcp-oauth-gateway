package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
)

// newRotateKeyCommand is the manual key-rotation ops command (SPEC §2.3):
// it forces one rotation in the on-disk key directory. It runs offline —
// a running gateway keeps its key set in memory, so it must be restarted
// afterwards to sign with the new key.
// rotateKeyOptions carries the rotate-key flags (same env twins as the
// server: DATA_PATH, KEY_ALG, ACCESS_TOKEN_TTL, CLOCK_SKEW).
type rotateKeyOptions struct {
	dataPath       string
	keyAlg         string
	accessTokenTTL time.Duration
	clockSkew      time.Duration
}

func newRotateKeyCommand() *cobra.Command {
	var opts rotateKeyOptions

	cmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate the signing key now (restart the gateway afterwards)",
		Long: `Force one signing-key rotation (SPEC §2.3): a new key becomes active and the
previous key keeps verifying outstanding tokens for ACCESS_TOKEN_TTL + 2×CLOCK_SKEW.

Run this against the gateway's data directory while the gateway is stopped, or
restart the gateway right afterwards — a running gateway keeps its key set in
memory: it neither picks up an on-disk rotation nor is it guaranteed to preserve
one on its next manifest write.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rotateKey(cmd, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.dataPath, "data-path", "d", getEnvWithDefault("DATA_PATH", "./data"), "Path to the data directory")
	cmd.Flags().StringVar(&opts.keyAlg, "key-alg", getEnvWithDefault("KEY_ALG", "RS256"), "JWS signing algorithm: RS256 or ES256")
	cmd.Flags().DurationVar(&opts.accessTokenTTL, "access-token-ttl", getEnvDurationWithDefault("ACCESS_TOKEN_TTL", time.Hour), "Access token lifetime (1m-24h); sets the retiring window")
	cmd.Flags().DurationVar(&opts.clockSkew, "clock-skew", getEnvDurationWithDefault("CLOCK_SKEW", 30*time.Second), "Clock-skew leeway (0-5m); widens the retiring window")

	return cmd
}

// rotateKey loads the key directory and forces one rotation. The retiring
// window mirrors the server's: ACCESS_TOKEN_TTL + 2×CLOCK_SKEW (SPEC §2.3.2),
// so every outstanding token stays verifiable until it has expired.
func rotateKey(cmd *cobra.Command, opts rotateKeyOptions) error {
	if os.Getenv("JWT_PRIVATE_KEY") != "" {
		return fmt.Errorf("key rotation is not available with an externally provided key (JWT_PRIVATE_KEY)")
	}
	alg, err := keys.ParseAlg(opts.keyAlg)
	if err != nil {
		return err
	}
	if opts.accessTokenTTL < time.Minute || opts.accessTokenTTL > 24*time.Hour {
		return fmt.Errorf("access token TTL must be between 1m and 24h, got: %s", opts.accessTokenTTL)
	}
	if opts.clockSkew < 0 || opts.clockSkew > 5*time.Minute {
		return fmt.Errorf("clock skew must be between 0 and 5m, got: %s", opts.clockSkew)
	}

	retireWindow := opts.accessTokenTTL + 2*opts.clockSkew
	manager, err := keys.NewManager(keys.Config{
		Dir:           filepath.Join(opts.dataPath, "keys"),
		Alg:           alg,
		LegacyKeyPath: filepath.Join(opts.dataPath, "private_key.pem"),
		RetireWindow:  retireWindow,
	})
	if err != nil {
		return err
	}

	previous := manager.Active()
	now := time.Now().UTC()
	if err := manager.Rotate(now); err != nil {
		return err
	}
	active := manager.Active()

	cmd.Printf("Rotated signing key: new active kid %s (%s); previous kid %s verifies until %s.\n",
		active.Kid, active.Alg, previous.Kid,
		now.Add(retireWindow).Format(time.RFC3339))
	cmd.Println("Restart the gateway to pick up the new key.")
	return nil
}
