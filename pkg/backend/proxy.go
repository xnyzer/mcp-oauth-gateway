package backend

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/version"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

var MCPClientInitTimeout = 1 * time.Minute

// MCPDiscoverProbeTimeout bounds the server/discover probe that opens every
// connection to the upstream. Protocol 2026-07-28 replaced the initialize
// handshake with it, so the probe goes first; an upstream that predates it
// should answer "method not found", but one that ignores unknown methods
// answers nothing — and on stdio nothing would otherwise mean waiting forever.
// After this long the backend falls back to the handshake, which makes it the
// start-up delay such an upstream costs.
var MCPDiscoverProbeTimeout = 5 * time.Second

type ProxyBackend struct {
	logger *zap.Logger
	cmd    []string
	errCh  chan error
	client *client.Client
}

func NewProxyBackend(logger *zap.Logger, cmd []string) Backend {
	return &ProxyBackend{
		logger: logger,
		cmd:    cmd,
		errCh:  nil,
	}
}

func (p *ProxyBackend) Run(ctx context.Context) (http.Handler, error) {
	if p.errCh != nil {
		return nil, fmt.Errorf("proxy backend is already running")
	}
	//nolint:gosec // G204: running an operator-configured stdio MCP upstream is this backend's purpose
	execCmd := exec.CommandContext(ctx, p.cmd[0], p.cmd[1:]...)
	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	stdin, err := execCmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	execCmd.Stderr = os.Stderr
	if err := execCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start exec command: %w", err)
	}
	p.errCh = make(chan error)
	done := make(chan struct{})
	go func() {
		if err := execCmd.Wait(); err != nil {
			p.errCh <- fmt.Errorf("exec command failed: %s: %w", strings.Join(p.cmd, " "), err)
		}
	}()
	var handler http.Handler
	go func() {
		tr := transport.NewIO(stdout, stdin, os.Stderr)
		transport.WithCommandLogger(newSlogLogger(p.logger))(tr)
		_client, _handler, err := setupProxy(ctx, p.logger, tr)
		if err != nil {
			p.errCh <- err
			return
		}
		p.client = _client
		handler = _handler
		done <- struct{}{}
	}()
	select {
	case err := <-p.errCh:
		return nil, err
	case <-done:
		return handler, nil
	}
}

func (p *ProxyBackend) Wait() error {
	if p.errCh == nil {
		return nil
	}
	return <-p.errCh
}

func (p *ProxyBackend) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

func setupProxy(ctx context.Context, logger *zap.Logger, tr transport.BidirectionalInterface) (*client.Client, http.Handler, error) {
	c := client.NewClient(tr, client.WithDiscoverTimeout(MCPDiscoverProbeTimeout))
	if err := c.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to start MCP client: %w", err)
	}
	initCtx, cancel := context.WithTimeout(ctx, MCPClientInitTimeout)
	defer cancel()

	// Ask for the newest protocol the library implements; the client
	// negotiates down to whatever the upstream speaks (see
	// docs/MCP-CONFORMANCE.md for what that comes to).
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "mcp-oauth-gateway",
				Version: version.Version,
			},
		},
	}
	init, err := c.Initialize(initCtx, initRequest)
	if err != nil {
		_ = c.Close() // best-effort cleanup on the failure path
		return nil, nil, fmt.Errorf("failed to initialize MCP client: %w", err)
	}
	s := server.NewMCPServer(init.ServerInfo.Name, init.ServerInfo.Version)
	if init.Capabilities.Tools != nil {
		tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
		if err != nil {
			_ = c.Close()
			return nil, nil, fmt.Errorf("failed to list tools: %w", err)
		}
		for _, tool := range tools.Tools {
			s.AddTool(tool, c.CallTool)
		}
	}
	if init.Capabilities.Prompts != nil {
		prompts, err := c.ListPrompts(ctx, mcp.ListPromptsRequest{})
		if err != nil {
			_ = c.Close()
			return nil, nil, fmt.Errorf("failed to list prompts: %w", err)
		}
		for _, prompt := range prompts.Prompts {
			s.AddPrompt(prompt, c.GetPrompt)
		}
	}
	if init.Capabilities.Resources != nil {
		resources, err := c.ListResources(ctx, mcp.ListResourcesRequest{})
		if err != nil {
			_ = c.Close()
			return nil, nil, fmt.Errorf("failed to list resources: %w", err)
		}
		for _, resource := range resources.Resources {
			s.AddResource(resource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				res, err := c.ReadResource(ctx, request)
				if err != nil {
					return nil, err
				}
				return res.Contents, nil
			})
		}
	}
	ss := server.NewStreamableHTTPServer(
		s,
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true),
		server.WithStreamableHTTPLogger(newSlogLogger(logger)),
	)
	return c, ss, nil
}

// newSlogLogger bridges the gateway's zap logger to the *slog.Logger that
// mcp-go now requires, having dropped its own logger interface. Wrapping the
// existing core rather than building a second logger keeps the stdio
// backend's output in the same structured stream as the rest of the gateway.
func newSlogLogger(logger *zap.Logger) *slog.Logger {
	return slog.New(zapslog.NewHandler(logger.Core()))
}
