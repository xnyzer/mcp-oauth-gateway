package backend

// Which MCP protocol version the stdio backend speaks (F-031c) — towards the
// upstream it drives, and towards the client it serves. These tests are the
// evidence behind the stdio paragraph in docs/MCP-CONFORMANCE.md, so they name
// the versions as literals: if a library update moves one, a test has to fail
// before the record can be wrong.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	currentProtocol    = "2026-07-28" // stateless: server/discover, no handshake
	lastHandshakeProto = "2025-11-25" // the newest revision with initialize
)

// -- A hand-written upstream that predates 2026-07-28 --------------------------

type discoverBehaviour int

const (
	// answersMethodNotFound is what a well-behaved older server does with a
	// method it does not know.
	answersMethodNotFound discoverBehaviour = iota
	// ignoresUnknownMethods is the awkward one: no reply at all.
	ignoresUnknownMethods
)

// legacyUpstream speaks just enough JSON-RPC to stand in for a stdio MCP server
// from before the stateless protocol: it has no server/discover, and answers
// initialize with a fixed protocol version.
type legacyUpstream struct {
	discover discoverBehaviour
	version  string // what it answers initialize with
	hasTool  bool   // offers a tool named "echo"

	mu                 sync.Mutex
	methods            []string
	versionAskedInInit string
}

type rpcRequest struct {
	ID     *json.RawMessage `json:"id"`
	Method string           `json:"method"`
	Params struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"params"`
}

// serve answers requests read from in on out until in is closed.
func (u *legacyUpstream) serve(in io.Reader, out io.Writer) {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		u.mu.Lock()
		u.methods = append(u.methods, req.Method)
		if req.Method == "initialize" {
			u.versionAskedInInit = req.Params.ProtocolVersion
		}
		u.mu.Unlock()
		if reply := u.reply(req); reply != nil {
			line, _ := json.Marshal(reply)
			_, _ = out.Write(append(line, '\n'))
		}
	}
}

func (u *legacyUpstream) reply(req rpcRequest) map[string]any {
	if req.ID == nil {
		return nil // a notification gets no reply
	}
	result := func(value map[string]any) map[string]any {
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": value}
	}
	switch {
	case req.Method == "initialize":
		capabilities := map[string]any{}
		if u.hasTool {
			capabilities["tools"] = map[string]any{}
		}
		return result(map[string]any{
			"protocolVersion": u.version,
			"capabilities":    capabilities,
			"serverInfo":      map[string]any{"name": "legacy-upstream", "version": "1.0"},
		})
	case req.Method == "tools/list" && u.hasTool:
		return result(map[string]any{"tools": []map[string]any{{
			"name": "echo", "description": "answers", "inputSchema": map[string]any{"type": "object"},
		}}})
	case req.Method == "tools/call" && u.hasTool:
		return result(map[string]any{"content": []map[string]any{{"type": "text", "text": "answered by the legacy upstream"}}})
	}
	if u.discover == ignoresUnknownMethods {
		return nil
	}
	return map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{
		"code": mcp.METHOD_NOT_FOUND, "message": "Method not found",
	}}
}

func (u *legacyUpstream) seen() (methods []string, versionAskedInInit string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.methods...), u.versionAskedInInit
}

// connect wires an upstream to a client transport over two in-memory pipes —
// what Run does with a child process's stdin and stdout.
func connect(t *testing.T, serve func(in io.Reader, out io.Writer)) transport.BidirectionalInterface {
	t.Helper()
	toUpstream, fromClient := io.Pipe() // the client writes, the upstream reads
	toClient, fromUpstream := io.Pipe() // the upstream writes, the client reads
	go serve(toUpstream, fromUpstream)
	t.Cleanup(func() {
		_ = fromClient.Close()
		_ = fromUpstream.Close()
	})
	return transport.NewIO(toClient, fromClient, io.NopCloser(strings.NewReader("")))
}

// currentUpstream is a real MCP server of the library's own version.
func currentUpstream(ctx context.Context) func(in io.Reader, out io.Writer) {
	return func(in io.Reader, out io.Writer) {
		_ = server.NewStdioServer(server.NewMCPServer("current-upstream", "1.0")).Listen(ctx, in, out)
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// -- Towards the upstream ------------------------------------------------------

func TestStdioBackendSpeaksTheCurrentProtocolToACurrentUpstream(t *testing.T) {
	ctx := testContext(t)

	c, handler, err := setupProxy(ctx, zap.NewNop(), connect(t, currentUpstream(ctx)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	require.NotNil(t, handler)
	require.Equal(t, currentProtocol, c.ProtocolVersion())
}

// An upstream from before 2026-07-28 has no server/discover. The backend falls
// back to the handshake, asks for the newest revision that still has one, and
// then speaks whatever the upstream answers with.
func TestStdioBackendFallsBackToTheHandshakeForAnOlderUpstream(t *testing.T) {
	for _, upstreamVersion := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"} {
		t.Run(upstreamVersion, func(t *testing.T) {
			ctx := testContext(t)
			upstream := &legacyUpstream{discover: answersMethodNotFound, version: upstreamVersion}

			c, _, err := setupProxy(ctx, zap.NewNop(), connect(t, upstream.serve))
			require.NoError(t, err)
			t.Cleanup(func() { _ = c.Close() })

			require.Equal(t, upstreamVersion, c.ProtocolVersion(), "the upstream's version is the one in effect")
			methods, asked := upstream.seen()
			require.Equal(t, []string{"server/discover", "initialize"}, methods[:2], "the probe goes first, the handshake second")
			require.Equal(t, lastHandshakeProto, asked, "the handshake cannot carry 2026-07-28")
		})
	}
}

// The awkward older upstream answers an unknown method with nothing. The probe
// is bounded, so start-up is delayed by MCPDiscoverProbeTimeout and no longer.
func TestStdioBackendWaitsOutAnUpstreamThatIgnoresTheProbe(t *testing.T) {
	const probe = 300 * time.Millisecond
	previous := MCPDiscoverProbeTimeout
	MCPDiscoverProbeTimeout = probe
	t.Cleanup(func() { MCPDiscoverProbeTimeout = previous })

	ctx := testContext(t)
	upstream := &legacyUpstream{discover: ignoresUnknownMethods, version: "2025-06-18"}

	started := time.Now()
	c, _, err := setupProxy(ctx, zap.NewNop(), connect(t, upstream.serve))
	waited := time.Since(started)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	require.Equal(t, "2025-06-18", c.ProtocolVersion())
	require.GreaterOrEqual(t, waited, probe, "the backend waited for the probe to time out")
	require.Less(t, waited, 10*probe, "and not for anything longer")
}

// An upstream that claims a protocol version nobody knows is refused rather
// than driven on a guess.
func TestStdioBackendRefusesAnUpstreamWithAnUnknownProtocolVersion(t *testing.T) {
	ctx := testContext(t)
	upstream := &legacyUpstream{discover: answersMethodNotFound, version: "1999-01-01"}

	c, handler, err := setupProxy(ctx, zap.NewNop(), connect(t, upstream.serve))

	require.Error(t, err)
	require.Contains(t, err.Error(), "1999-01-01")
	require.Nil(t, c)
	require.Nil(t, handler)
}

// The library default is not what the gateway relies on: the bound is the
// gateway's own, named value.
func TestDiscoverProbeTimeoutIsFiveSeconds(t *testing.T) {
	require.Equal(t, 5*time.Second, MCPDiscoverProbeTimeout)
}

// -- Towards the client --------------------------------------------------------

// The handler the backend returns is what an MCP client such as Claude talks
// to. It serves the current protocol, and the handshake revisions for clients
// that have not moved yet.
func TestStdioBackendServesCurrentAndOlderClients(t *testing.T) {
	ctx := testContext(t)
	upstreamClient, handler, err := setupProxy(ctx, zap.NewNop(), connect(t, currentUpstream(ctx)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstreamClient.Close() })

	gateway := httptest.NewServer(handler)
	t.Cleanup(gateway.Close)

	cases := []struct {
		name    string
		options []client.ClientOption
		want    string
	}{
		{"a current client", nil, currentProtocol},
		{"a client pinned to 2025-11-25", []client.ClientOption{client.WithProtocolVersion("2025-11-25")}, "2025-11-25"},
		{"a client pinned to 2025-06-18", []client.ClientOption{client.WithProtocolVersion("2025-06-18")}, "2025-06-18"},
		{"a client pinned to 2025-03-26", []client.ClientOption{client.WithProtocolVersion("2025-03-26")}, "2025-03-26"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := transport.NewStreamableHTTP(gateway.URL + "/mcp")
			require.NoError(t, err)
			mcpClient := client.NewClient(tr, tc.options...)
			t.Cleanup(func() { _ = mcpClient.Close() })
			require.NoError(t, mcpClient.Start(ctx))

			result, err := mcpClient.Initialize(ctx, mcp.InitializeRequest{})
			require.NoError(t, err)

			require.Equal(t, tc.want, mcpClient.ProtocolVersion())
			require.Equal(t, "current-upstream", result.ServerInfo.Name, "the upstream's identity is passed through")
			require.Equal(t, "1.0", result.ServerInfo.Version, "and so is its version")
		})
	}
}

// The case that matters in practice: a current client in front of an upstream
// that has not moved. The backend speaks 2026-07-28 on one side and the
// handshake protocol on the other, and a tool call still goes through.
func TestStdioBackendBridgesACurrentClientToAnOlderUpstream(t *testing.T) {
	ctx := testContext(t)
	upstream := &legacyUpstream{discover: answersMethodNotFound, version: "2025-06-18", hasTool: true}
	upstreamClient, handler, err := setupProxy(ctx, zap.NewNop(), connect(t, upstream.serve))
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstreamClient.Close() })
	require.Equal(t, "2025-06-18", upstreamClient.ProtocolVersion(), "towards the upstream")

	gateway := httptest.NewServer(handler)
	t.Cleanup(gateway.Close)
	tr, err := transport.NewStreamableHTTP(gateway.URL + "/mcp")
	require.NoError(t, err)
	mcpClient := client.NewClient(tr)
	t.Cleanup(func() { _ = mcpClient.Close() })
	require.NoError(t, mcpClient.Start(ctx))
	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err)
	require.Equal(t, currentProtocol, mcpClient.ProtocolVersion(), "towards the client")

	tools, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, tools.Tools, 1)
	require.Equal(t, "echo", tools.Tools[0].Name)

	called, err := mcpClient.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "echo"}})
	require.NoError(t, err)
	require.Len(t, called.Content, 1)
	text, ok := called.Content[0].(mcp.TextContent)
	require.True(t, ok, "the tool result is text")
	require.Equal(t, "answered by the legacy upstream", text.Text)
}
