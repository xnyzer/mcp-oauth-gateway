package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHealthURL(t *testing.T) {
	cases := []struct {
		listen  string
		want    string
		wantErr bool
	}{
		{listen: ":8080", want: "http://127.0.0.1:8080/healthz"},
		{listen: "0.0.0.0:8080", want: "http://127.0.0.1:8080/healthz"},
		{listen: "[::]:8080", want: "http://127.0.0.1:8080/healthz"},
		{listen: "10.0.0.5:8080", want: "http://10.0.0.5:8080/healthz"},
		{listen: "127.0.0.1:80", want: "http://127.0.0.1:80/healthz"},
		{listen: "no-port", wantErr: true},
	}
	for _, tt := range cases {
		t.Run(tt.listen, func(t *testing.T) {
			got, err := healthURL(tt.listen)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestHealthcheckCommand drives the container health probe against stub
// servers: only a plain 200 counts as healthy — errors, non-200 and
// redirects (an https-redirecting listener without the /healthz
// passthrough) must fail.
func TestHealthcheckCommand(t *testing.T) {
	runProbe := func(t *testing.T, listen string) error {
		t.Helper()
		cmd := newRootCommand(nil)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"healthcheck", "--listen", listen, "--timeout", "2s"})
		return cmd.Execute()
	}

	t.Run("healthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		require.NoError(t, runProbe(t, strings.TrimPrefix(srv.URL, "http://")))
	})

	t.Run("unhealthy status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		err := runProbe(t, strings.TrimPrefix(srv.URL, "http://"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "503")
	})

	t.Run("redirect is not healthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com"+r.RequestURI, http.StatusMovedPermanently)
		}))
		defer srv.Close()
		err := runProbe(t, strings.TrimPrefix(srv.URL, "http://"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "301")
	})

	t.Run("no listener", func(t *testing.T) {
		require.Error(t, runProbe(t, "127.0.0.1:1"))
	})
}
