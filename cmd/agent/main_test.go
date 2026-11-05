package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/network-enforcer/internal/tailer"
)

func TestRunTailsAndStops(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))

	var mu sync.Mutex
	var got []string
	h := func(l tailer.Line) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, string(l.Raw))
	}

	cfg := tailer.Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, h, logger) }()

	time.Sleep(100 * time.Millisecond)
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = fmt.Fprintln(f, "2026-10-29T13:00:00.000000001Z stdout F hello")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 1
	}, 3*time.Second, 20*time.Millisecond)

	cancel()
	select {
	case errRun := <-done:
		require.NoError(t, errRun)
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after the context was canceled")
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"2026-10-29T13:00:00.000000001Z stdout F hello"}, got)
}
