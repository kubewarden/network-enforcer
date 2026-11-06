package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/tailer"
)

func TestRunAgentWritesParsedEventsToDurableBuffer(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(logs, 0o700))
	logPath := filepath.Join(logs, "0.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))
	stateDir := filepath.Join(root, "state")
	cfg := tailer.Config{Include: []string{filepath.Join(logs, "*.log")}, PollInterval: 15 * time.Millisecond}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, cfg, stateDir, logger) }()

	time.Sleep(80 * time.Millisecond)
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = fmt.Fprintln(
		file,
		`2026-11-02T00:00:00.123Z stdout F {"message":"deny policy match","policy":"ns/deny","proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}}`,
	)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	type stateSummary struct {
		NewestSeq uint64 `json:"newestSeq"`
	}
	type envelopeSummary struct {
		State json.RawMessage `json:"state"`
	}
	require.Eventually(t, func() bool {
		raw, readErr := os.ReadFile(filepath.Join(stateDir, "agent-state.json"))
		if readErr != nil {
			return false
		}
		var envelope envelopeSummary
		if json.Unmarshal(raw, &envelope) != nil {
			return false
		}
		var state stateSummary
		return json.Unmarshal(envelope.State, &state) == nil && state.NewestSeq == 1
	}, 3*time.Second, 15*time.Millisecond)
	cancel()
	select {
	case runErr := <-done:
		require.NoError(t, runErr)
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not stop after cancellation")
	}

	buffer, recovered, err := agentbuffer.Open(stateDir, agentbuffer.Config{})
	require.NoError(t, err)
	require.True(t, recovered)
	status, err := buffer.GetStatus(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, uint64(1), status.GetNewestSeq())
	require.Equal(t, uint64(1), status.GetReceivedEvents())
	require.NoError(t, buffer.Close())
}
