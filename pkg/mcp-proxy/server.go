package mcpproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/tlsreload"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// serverGroup runs the listeners and collects what they report. The first one
// to stop ends the process: a gateway serving on only half its listeners is a
// silent half-outage, so it exits and lets the supervisor restart it.
type serverGroup struct {
	logger *zap.Logger

	wg   sync.WaitGroup
	exit chan struct{}

	mu   sync.Mutex
	errs []error
}

func newServerGroup(logger *zap.Logger) *serverGroup {
	// Buffered so a listener stopping after the first one was already
	// observed still delivers instead of blocking its goroutine forever.
	return &serverGroup{logger: logger, exit: make(chan struct{}, 3)}
}

func (g *serverGroup) fail(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.errs = append(g.errs, err)
}

// serve runs one HTTP server until it stops, and shuts it down gracefully when
// ctx is cancelled. A closed server is a normal stop, not an error. Whether it
// serves TLS is decided by the server's own TLSConfig.
func (g *serverGroup) serve(ctx context.Context, srv *http.Server, name string) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		var err error
		if srv.TLSConfig != nil {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.fail(err)
		}
		g.logger.Debug(name + " server closed")
		g.exit <- struct{}{}
	}()

	// The shutdown context is deliberately NOT derived from ctx: ctx is already
	// cancelled by the time this runs — that is why we are shutting down — and a
	// cancelled parent would make Shutdown return at once instead of draining
	// in-flight requests.
	//nolint:gosec // G118: the detached context is the point, see above
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			g.logger.Warn(name+" server shutdown error", zap.Error(err))
		}
	}()
}

// watchUpstream ends the process when the upstream backend does — a stdio
// upstream that dies would otherwise leave the gateway serving errors.
func (g *serverGroup) watchUpstream(ctx context.Context, deps *dependencies) {
	if deps.upstreamBackend == nil {
		return
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if err := deps.upstreamBackend.Wait(); err != nil && !errors.Is(ctx.Err(), context.Canceled) {
			g.fail(err)
		}
		g.logger.Debug("proxy backend closed")
		g.exit <- struct{}{}
	}()
}

// wait blocks until the first listener stops, then cancels the rest and
// collects their errors.
func (g *serverGroup) wait(stop context.CancelFunc) error {
	<-g.exit
	stop()
	g.wg.Wait()
	g.mu.Lock()
	defer g.mu.Unlock()
	return errors.Join(g.errs...)
}

// gateway is the assembled gateway, ready to serve. It constructs nothing:
// everything it serves came from buildRouter, which is what keeps that wiring
// testable without a listener.
type gateway struct {
	rc     resolvedConfig
	deps   *dependencies
	router *gin.Engine
	group  *serverGroup
}

func newGateway(rc resolvedConfig, deps *dependencies, router *gin.Engine) *gateway {
	return &gateway{rc: rc, deps: deps, router: router, group: newServerGroup(deps.logger)}
}

// serve starts the listeners for the configured TLS mode and blocks until the
// gateway stops.
func (g *gateway) serve(ctx context.Context, stop context.CancelFunc) error {
	acmeHost, autoDetected := g.rc.acmeHost()

	switch {
	case g.rc.manualTLS:
		if err := g.serveManualTLS(ctx); err != nil {
			return err
		}
	case acmeHost != "":
		if err := g.serveACME(ctx, acmeHost, autoDetected); err != nil {
			return err
		}
	default:
		g.group.serve(ctx, &http.Server{
			Addr:              g.rc.Listen,
			Handler:           g.router,
			ReadHeaderTimeout: readHeaderTimeout,
		}, "HTTP")
	}

	g.group.watchUpstream(ctx, g.deps)

	listeners := []string{g.rc.Listen}
	if g.rc.manualTLS || acmeHost != "" {
		listeners = append(listeners, g.rc.TLSListen)
	}
	g.deps.logger.Info("Starting server", zap.Strings("listen", listeners))

	return g.group.wait(stop)
}

// serveManualTLS serves a supplied certificate pair, reloaded from disk when it
// changes, with plain HTTP redirecting to https.
func (g *gateway) serveManualTLS(ctx context.Context) error {
	certReloader, err := tlsreload.NewFileReloader(g.rc.TLSCertFile, g.rc.TLSKeyFile, g.deps.logger)
	if err != nil {
		return fmt.Errorf("failed to prepare TLS certificate reloader: %w", err)
	}
	g.deps.logger.Info("Starting server with provided TLS certificate")

	g.group.serve(ctx, &http.Server{
		Addr:              g.rc.Listen,
		Handler:           httpFallbackHandler(),
		ReadHeaderTimeout: readHeaderTimeout,
	}, "HTTP")
	g.group.serve(ctx, &http.Server{
		Addr:              g.rc.TLSListen,
		Handler:           g.router,
		TLSConfig:         &tls.Config{GetCertificate: certReloader.GetCertificate},
		ReadHeaderTimeout: readHeaderTimeout,
	}, "HTTPS")
	return nil
}

// serveACME serves a certificate obtained through built-in ACME. The plain
// listener carries the HTTP-01 challenge, which is why it must stay reachable.
func (g *gateway) serveACME(ctx context.Context, host string, autoDetected bool) error {
	if !g.rc.TLSAcceptTOS {
		if autoDetected {
			return errors.New("TLS host is auto-detected, but tlsAcceptTOS is not set to true. Please agree to the TOS or set noAutoTLS to true")
		}
		return errors.New("TLS is enabled, but tlsAcceptTOS is not set to true. Please explicitly agree to the TOS")
	}

	m := autocert.Manager{
		Prompt:     func(string) bool { return g.rc.TLSAcceptTOS },
		HostPolicy: autocert.HostWhitelist(host),
		Cache:      autocert.DirCache(path.Join(g.rc.DataPath, "certs")),
		Client:     &acme.Client{DirectoryURL: g.rc.TLSDirectoryURL},
	}

	g.group.serve(ctx, &http.Server{
		Addr:              g.rc.Listen,
		Handler:           m.HTTPHandler(httpFallbackHandler()),
		ReadHeaderTimeout: readHeaderTimeout,
	}, "HTTP")
	g.group.serve(ctx, &http.Server{
		Addr:              g.rc.TLSListen,
		Handler:           g.router,
		TLSConfig:         m.TLSConfig(),
		ReadHeaderTimeout: readHeaderTimeout,
	}, "HTTPS")
	return nil
}

// acmeHost reports the host built-in ACME should obtain a certificate for, and
// whether it was derived from EXTERNAL_URL rather than configured outright.
// The distinction only matters for the error message when the TOS were not
// accepted: an operator who never asked for TLS deserves to be told why it
// switched itself on.
func (rc resolvedConfig) acmeHost() (host string, autoDetected bool) {
	if rc.TLSHost != "" {
		return rc.TLSHost, false
	}
	if rc.AutoTLS && !rc.manualTLS &&
		rc.issuerURL.Scheme == "https" &&
		rc.issuerURL.Host != "localhost" {
		return rc.issuerURL.Host, true
	}
	return "", false
}
