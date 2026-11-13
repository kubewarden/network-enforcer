package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/grpcexporter"
	"github.com/kubewarden/network-enforcer/internal/tailer"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

func startTestAgent(t *testing.T, cfg tailer.Config, buffer *agentbuffer.Buffer) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	logger := slog.New(slog.DiscardHandler)
	go func() { done <- runAgent(ctx, cfg, buffer, nil, nil, logger) }()
	var once sync.Once
	stop := func() {
		t.Helper()
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(3 * time.Second):
				t.Fatal("agent did not stop after cancellation")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func appendAgentLine(t *testing.T, path, body string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = fmt.Fprintln(file, "2026-11-02T00:00:00Z stdout F "+body)
	require.NoError(t, err)
	require.NoError(t, file.Close())
}

func waitForAgentInput(t *testing.T, path string, buffer *agentbuffer.Buffer) {
	t.Helper()
	require.Eventually(t, func() bool {
		status, err := buffer.GetStatus(t.Context(), nil)
		require.NoError(t, err)
		if status.GetReceivedEvents() > 0 {
			return true
		}
		appendAgentLine(t, path, `{"message":"ignored readiness record"}`)
		return false
	}, 3*time.Second, 15*time.Millisecond)
}

func TestRunAgentTailsOnlyNewLinesWithoutPersistentState(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "0.log")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	appendAgentLine(t, path, `{"message":"deny policy match","policy":"history"}`)
	cfg := tailer.Config{
		Include: []string{filepath.Join(root, "*.log")}, PollInterval: 15 * time.Millisecond,
		StatePath: filepath.Join(root, "unused-checkpoint.json"), StartAt: "beginning",
	}
	buffer := agentbuffer.New()
	stop := startTestAgent(t, cfg, buffer)
	waitForAgentInput(t, path, buffer)
	empty, err := buffer.ScrapeEvents(t.Context(), nil)
	require.NoError(t, err)
	require.Empty(t, empty.GetEvents(), "existing log history must not be replayed")

	appendAgentLine(t, path, `{"message":"deny policy match","policy":"new","proxy":{"wl":"ns/pod"}}`)
	require.Eventually(t, func() bool {
		status, statusErr := buffer.GetStatus(t.Context(), nil)
		return statusErr == nil && status.GetBufferedEvents() == 1
	}, 3*time.Second, 15*time.Millisecond)
	stop()
	response, err := buffer.ScrapeEvents(t.Context(), &agentv1.ScrapeEventsRequest{})
	require.NoError(t, err)
	require.Len(t, response.GetEvents(), 1)
	require.Equal(t, "new", response.GetEvents()[0].GetPolicy().GetPolicy())
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, entries, 1, "agent must not write checkpoints or snapshots")

	restarted := agentbuffer.New()
	stopRestarted := startTestAgent(t, cfg, restarted)
	waitForAgentInput(t, path, restarted)
	stopRestarted()
	response, err = restarted.ScrapeEvents(t.Context(), nil)
	require.NoError(t, err)
	require.Empty(t, response.GetEvents(), "restart must not replay old events")
}

func TestRunAgentServesBufferedEventsOverGRPC(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "0.log")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	cfg := tailer.Config{
		Include: []string{filepath.Join(root, "*.log")}, PollInterval: 15 * time.Millisecond,
	}
	buffer := agentbuffer.New()
	logger := slog.New(slog.DiscardHandler)

	srv, err := grpcexporter.NewServer(grpcexporter.ServerConfig{MTLSEnabled: false}, buffer, logger)
	require.NoError(t, err)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, cfg, buffer, srv, lis, logger) }()
	t.Cleanup(func() {
		cancel()
		select {
		case runErr := <-done:
			require.NoError(t, runErr)
		case <-time.After(3 * time.Second):
			t.Fatal("agent did not stop after cancellation")
		}
	})

	waitForAgentInput(t, path, buffer)
	appendAgentLine(t, path, `{"message":"deny policy match","policy":"new","proxy":{"wl":"ns/pod"}}`)
	require.Eventually(t, func() bool {
		status, statusErr := buffer.GetStatus(t.Context(), nil)
		return statusErr == nil && status.GetBufferedEvents() == 1
	}, 3*time.Second, 15*time.Millisecond)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	resp, err := agentv1.NewAgentServiceClient(conn).ScrapeEvents(ctx, &agentv1.ScrapeEventsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetEvents(), 1)
	require.Equal(t, "new", resp.GetEvents()[0].GetPolicy().GetPolicy())
}

func TestRunAgentObservesMatchingFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "0.log")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	buffer := agentbuffer.New()
	stop := startTestAgent(t, tailer.Config{
		Include: []string{filepath.Join(root, "*.log")}, PollInterval: 15 * time.Millisecond,
	}, buffer)
	require.Eventually(t, func() bool {
		status, err := buffer.GetStatus(t.Context(), nil)
		return err == nil && len(status.GetCurrentLogFiles()) == 1 && status.GetCurrentLogFiles()[0] == path
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, os.Rename(path, path+".1"))
	require.Eventually(t, func() bool {
		status, err := buffer.GetStatus(t.Context(), nil)
		return err == nil && len(status.GetCurrentLogFiles()) == 0
	}, 3*time.Second, 15*time.Millisecond)
	stop()
}
