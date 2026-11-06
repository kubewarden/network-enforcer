package agentbuffer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/extension/xextension/storage"

	"github.com/kubewarden/network-enforcer/internal/tailer"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

func agentTailerConfig(dir string, b *Buffer, start string) tailer.Config {
	return tailer.Config{
		Include: []string{filepath.Join(dir, "*.log")}, PollInterval: 15 * time.Millisecond,
		StartAt: start, CheckpointStore: b, PersistenceError: b.Err,
		OnFilesObserved: b.SetCurrentLogFiles,
	}
}

func appendCRI(t *testing.T, path string, body string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = fmt.Fprintln(file, "2026-11-02T00:00:00.123Z stdout F "+body)
	require.NoError(t, err)
	require.NoError(t, file.Close())
}

type droppingCheckpointStore struct {
	operator.Persister

	buffer  *Buffer
	drop    atomic.Bool
	dropped chan struct{}
	once    sync.Once
}

func (s *droppingCheckpointStore) Batch(ctx context.Context, ops ...*storage.Operation) error {
	if s.drop.Load() {
		s.buffer.mu.Lock()
		hasStagedEvent := s.buffer.pendingSeq > 0
		s.buffer.mu.Unlock()
		if hasStagedEvent {
			s.once.Do(func() { close(s.dropped) })
			return nil
		}
	}
	return s.Persister.Batch(ctx, ops...)
}

func TestTailerCheckpointAtomicallyPublishesEventsAndPaths(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(logs, 0o700))
	logPath := filepath.Join(logs, "0.log")
	appendCRI(t, logPath, `{"message":"ordinary ignored log"}`)
	b, recovered := openTestBuffer(t, filepath.Join(root, "state"), testConfig())
	require.False(t, recovered)
	tl, err := tailer.New(
		agentTailerConfig(logs, b, "end"),
		func(line tailer.Line) { b.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, tl.Start())
	time.Sleep(80 * time.Millisecond)
	statusBeforeWrite, err := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Zero(t, statusBeforeWrite.GetReceivedEvents(), "fresh start-at-end should not consume existing history")

	appendCRI(
		t,
		logPath,
		`{"message":"deny policy match","policy":"ns/deny","proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}}`,
	)
	require.Eventually(t, func() bool {
		status, statusErr := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && status.GetReceivedEvents() == 1 && status.GetNewestSeq() == 1
	}, 3*time.Second, 15*time.Millisecond)
	b.mu.Lock()
	checkpointCommitted := len(b.state.KnownFiles) > 0
	b.mu.Unlock()
	require.True(t, checkpointCommitted, "the knownFiles checkpoint is committed with staged events")
	require.Eventually(t, func() bool {
		status, statusErr := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && len(status.GetCurrentLogFiles()) == 1 && status.GetCurrentLogFiles()[0] == logPath
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, tl.Stop())

	require.NoError(t, b.Close())
	reopened, recovered, err := Open(filepath.Join(root, "state"), testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	require.Equal(t, uint64(1), reopened.state.NewestSeq)
	require.Equal(t, uint64(1), reopened.state.ReceivedEvents)
	resp, err := reopened.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetEvents(), 1)
	require.Equal(t, protectDenyMessage, resp.GetEvents()[0].GetPolicy().GetMessage())
	require.NoError(t, reopened.Close())
}

func TestCrashBeforeFirstTailerCheckpointReplaysExactlyOnce(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(logs, 0o700))
	logPath := filepath.Join(logs, "0.log")
	appendCRI(t, logPath, `{"message":"deny policy match","proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}}`)
	stateDir := filepath.Join(root, "state")
	first, fresh := openTestBuffer(t, stateDir, testConfig())
	require.False(t, fresh)
	wrapper := &droppingCheckpointStore{Persister: first, buffer: first, dropped: make(chan struct{})}
	wrapper.drop.Store(true)
	cfg := agentTailerConfig(logs, first, "beginning")
	cfg.CheckpointStore = wrapper
	tl, err := tailer.New(cfg, func(line tailer.Line) { first.StageLine(line.Raw, line.ReadAt) })
	require.NoError(t, err)
	require.NoError(t, tl.Start())
	select {
	case <-wrapper.dropped:
	case <-time.After(3 * time.Second):
		t.Fatal("tailer did not stage and checkpoint the first event")
	}
	firstStatus, err := first.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Zero(t, firstStatus.GetNewestSeq(), "suppressed first checkpoint cannot expose a sequence")
	require.NoError(t, tl.Stop())
	require.NoError(t, first.Close())

	replayed, recovered, err := Open(stateDir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	require.Nil(t, replayed.state.KnownFiles, "the simulated crash left no offset checkpoint")
	replayTailer, err := tailer.New(
		agentTailerConfig(logs, replayed, "beginning"),
		func(line tailer.Line) { replayed.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, replayTailer.Start())
	require.Eventually(t, func() bool {
		status, statusErr := replayed.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && status.GetNewestSeq() == 1 && status.GetReceivedEvents() == 1
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, replayTailer.Stop())
	require.NoError(t, replayed.Close())
}

func TestTailerRestartAndSuppressedCommitReplayOnlyUncommittedLines(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(logs, 0o700))
	logPath := filepath.Join(logs, "0.log")
	appendCRI(t, logPath, `{"message":"deny policy match","proxy":{"wl":"ns/one"},"inbound":{"peer":"10.0.0.1:1"}}`)
	stateDir := filepath.Join(root, "state")
	buffer, _ := openTestBuffer(t, stateDir, testConfig())
	firstTailer, err := tailer.New(
		agentTailerConfig(logs, buffer, "beginning"),
		func(line tailer.Line) { buffer.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, firstTailer.Start())
	require.Eventually(t, func() bool {
		buffer.mu.Lock()
		defer buffer.mu.Unlock()
		return len(buffer.state.KnownFiles) > 0
	}, 3*time.Second, 15*time.Millisecond)
	require.Eventually(t, func() bool {
		status, statusErr := buffer.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && status.GetNewestSeq() == 1
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, firstTailer.Stop())
	require.NoError(t, buffer.Close())

	buffer, recovered, err := Open(stateDir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	resumeTailer, err := tailer.New(
		agentTailerConfig(logs, buffer, "beginning"),
		func(line tailer.Line) { buffer.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, resumeTailer.Start())
	time.Sleep(80 * time.Millisecond)
	resumeStatus, err := buffer.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(
		t,
		uint64(1),
		resumeStatus.GetNewestSeq(),
		"resume from a nonempty checkpoint must not duplicate committed lines",
	)
	require.NoError(t, resumeTailer.Stop())
	require.NoError(t, buffer.Close())

	buffer, recovered, err = Open(stateDir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	wrapper := &droppingCheckpointStore{Persister: buffer, buffer: buffer, dropped: make(chan struct{})}
	wrapper.drop.Store(true)
	cfg := agentTailerConfig(logs, buffer, "beginning")
	cfg.CheckpointStore = wrapper
	crashTailer, err := tailer.New(cfg, func(line tailer.Line) { buffer.StageLine(line.Raw, line.ReadAt) })
	require.NoError(t, err)
	require.NoError(t, crashTailer.Start())
	time.Sleep(80 * time.Millisecond)
	crashStatus, err := buffer.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(1), crashStatus.GetNewestSeq(), "already committed records stay committed on restart")
	appendCRI(t, logPath, `{"message":"deny policy match","proxy":{"wl":"ns/two"},"inbound":{"peer":"10.0.0.2:2"}}`)
	select {
	case <-wrapper.dropped:
	case <-time.After(3 * time.Second):
		t.Fatal("checkpoint wrapper did not suppress the staged line")
	}
	pendingStatus, err := buffer.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(
		t,
		uint64(1),
		pendingStatus.GetNewestSeq(),
		"the second staged line is not published before its checkpoint",
	)
	require.NoError(t, crashTailer.Stop())
	require.NoError(t, buffer.Close())

	buffer, recovered, err = Open(stateDir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	finalTailer, err := tailer.New(
		agentTailerConfig(logs, buffer, "beginning"),
		func(line tailer.Line) { buffer.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, finalTailer.Start())
	require.Eventually(t, func() bool {
		status, statusErr := buffer.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && status.GetNewestSeq() == 2 && status.GetReceivedEvents() == 2
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, finalTailer.Stop())
	response, err := buffer.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2}, eventSequences(response.GetEvents()))
	require.NoError(t, buffer.Close())
}

func TestReopenAfterNoFilePollReplaysNewFileFromBeginning(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(logs, 0o700))
	stateDir := filepath.Join(root, "state")
	first, recovered := openTestBuffer(t, stateDir, testConfig())
	require.False(t, recovered)
	tl1, err := tailer.New(
		agentTailerConfig(logs, first, "end"),
		func(line tailer.Line) { first.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, tl1.Start())
	time.Sleep(70 * time.Millisecond)
	require.NoError(t, tl1.Stop())
	require.NoError(t, first.Close())

	second, recovered, err := Open(stateDir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	logPath := filepath.Join(logs, "new.log")
	appendCRI(t, logPath, `{"message":"deny policy match","proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}}`)
	tl2, err := tailer.New(
		agentTailerConfig(logs, second, "beginning"),
		func(line tailer.Line) { second.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, tl2.Start())
	require.Eventually(t, func() bool {
		status, statusErr := second.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && status.GetNewestSeq() == 1
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, tl2.Stop())
	require.NoError(t, second.Close())
}

func TestTailerReportsFailedBatchAtStopAndDoesNotPublish(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(logs, 0o700))
	logPath := filepath.Join(logs, "0.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))
	stateDir := filepath.Join(root, "state")
	b, _ := openTestBuffer(t, stateDir, testConfig())
	tl, err := tailer.New(
		agentTailerConfig(logs, b, "end"),
		func(line tailer.Line) { b.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, tl.Start())
	time.Sleep(70 * time.Millisecond)
	require.NoError(t, os.RemoveAll(stateDir))
	appendCRI(t, logPath, `{"message":"deny policy match","proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}}`)
	require.Eventually(t, func() bool { return b.Err() != nil }, 3*time.Second, 15*time.Millisecond)
	b.mu.Lock()
	newest := b.state.NewestSeq
	b.mu.Unlock()
	require.Zero(t, newest, "failed checkpoint cannot publish event identity")
	require.Error(t, tl.Stop(), "stanza logs poll failures and returns nil; tailer surfaces the latched store error")
	require.NoError(t, b.Close())
}

func TestCurrentLogFilesTrackMatcherEmptyRenameAndRemoval(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	require.NoError(t, os.Mkdir(logs, 0o700))
	active := filepath.Join(logs, "0.log")
	require.NoError(t, os.WriteFile(active, nil, 0o600))
	b, _ := openTestBuffer(t, filepath.Join(root, "state"), testConfig())
	tl, err := tailer.New(
		agentTailerConfig(logs, b, "end"),
		func(line tailer.Line) { b.StageLine(line.Raw, line.ReadAt) },
	)
	require.NoError(t, err)
	require.NoError(t, tl.Start())
	require.Eventually(t, func() bool {
		status, statusErr := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && len(status.GetCurrentLogFiles()) == 1 && status.GetCurrentLogFiles()[0] == active
	}, 3*time.Second, 15*time.Millisecond)

	rotated := active + ".1"
	require.NoError(t, os.Rename(active, rotated))
	require.Eventually(t, func() bool {
		status, statusErr := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && len(status.GetCurrentLogFiles()) == 0
	}, 3*time.Second, 15*time.Millisecond)

	require.NoError(t, os.WriteFile(active, nil, 0o600))
	require.Eventually(t, func() bool {
		status, statusErr := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && len(status.GetCurrentLogFiles()) == 1 && status.GetCurrentLogFiles()[0] == active
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, os.Remove(active))
	require.Eventually(t, func() bool {
		status, statusErr := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
		return statusErr == nil && len(status.GetCurrentLogFiles()) == 0
	}, 3*time.Second, 15*time.Millisecond)
	require.NoError(t, tl.Stop())
	require.NoError(t, b.Close())
}
