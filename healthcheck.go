package main

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// newHealthcheckCommand probes a running gateway's /healthz for container
// health checks (SPEC §1.13) — the image has no shell or curl, so the
// binary probes itself. The plain-HTTP listener serves /healthz in every
// TLS mode, so probing LISTEN always works.
func newHealthcheckCommand() *cobra.Command {
	var listen string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:           "healthcheck",
		Short:         "Probe the running gateway's health endpoint",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return probeHealth(listen, timeout)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", getEnvWithDefault("LISTEN", ":80"), "Listen address of the running gateway")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Probe timeout")

	return cmd
}

// probeHealth GETs /healthz on the local listener and fails on anything
// but 200 — including redirects, which mean the health passthrough is
// missing (fail-closed: never report healthy on ambiguity).
func probeHealth(listen string, timeout time.Duration) error {
	url, err := healthURL(listen)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("health probe failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned status %d", resp.StatusCode)
	}
	return nil
}

// healthURL derives the local probe URL from a LISTEN value like ":8080",
// "0.0.0.0:8080" or "10.0.0.5:8080" (wildcard hosts probe loopback).
func healthURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}
