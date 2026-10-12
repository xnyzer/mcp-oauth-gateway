package backend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestProxyBackendRunWithInvalidCommand(t *testing.T) {
	logger := zap.NewNop()
	pb := NewProxyBackend(logger, []string{"sh", "-c", "exit 0"})
	defer pb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	handler, err := pb.Run(ctx)
	require.Error(t, err, "expected error for invalid command")
	require.Nil(t, handler, "handler should be nil on error")
}

func TestProxyBackendRun(t *testing.T) {
	logger := zap.NewNop()
	cmd := []string{"go", "run", "./testserver"}
	pb := NewProxyBackend(logger, cmd)
	defer pb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	handler, err := pb.Run(ctx)
	require.NoError(t, err, "Run should not return error")
	require.NotNil(t, handler, "handler should not be nil")

	checkCh := make(chan struct{})
	go func() {
		pb.Wait()
		close(checkCh)
	}()

	timeout := time.After(10 * time.Millisecond)
	select {
	case <-checkCh:
		t.Error("Test completed too early")
	case <-timeout:
		// Test timed out
	}

	cancel()

	timeout = time.After(10 * time.Second)
	select {
	case <-checkCh:
		// Test completed successfully
	case <-timeout:
		t.Error("Test timed out")
	}
}

// TestNewSlogLoggerWritesToZap pins down what the bridge is for: mcp-go's
// slog output has to land in the gateway's own zap stream, not in a second
// sink. Type compatibility alone would still compile with a discarded core.
func TestNewSlogLoggerWritesToZap(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)

	newSlogLogger(zap.New(core)).Info("stdio backend says hello", "attempt", 2)

	require.Equal(t, 1, logs.Len(), "the record should reach the zap core")
	entry := logs.All()[0]
	require.Equal(t, "stdio backend says hello", entry.Message)
	require.Equal(t, zapcore.InfoLevel, entry.Level)
	require.Equal(t, int64(2), entry.ContextMap()["attempt"], "slog attributes should survive the bridge")
}
