package tailer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigApplyDefaults(t *testing.T) {
	cases := []struct {
		name         string
		in           Config
		wantPoll     time.Duration
		wantStartAt  string
		wantTruncate string
	}{
		{
			name:         "empty config gets defaults",
			in:           Config{},
			wantPoll:     defaultPollInterval,
			wantStartAt:  "end",
			wantTruncate: "read_new",
		},
		{
			name:         "set values are kept",
			in:           Config{PollInterval: time.Second, StartAt: "beginning", OnTruncate: "ignore"},
			wantPoll:     time.Second,
			wantStartAt:  "beginning",
			wantTruncate: "ignore",
		},
		{
			name:         "non-positive poll falls back to default",
			in:           Config{PollInterval: -1},
			wantPoll:     defaultPollInterval,
			wantStartAt:  "end",
			wantTruncate: "read_new",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.in
			cfg.applyDefaults()
			assert.Equal(t, c.wantPoll, cfg.PollInterval)
			assert.Equal(t, c.wantStartAt, cfg.StartAt)
			assert.Equal(t, c.wantTruncate, cfg.OnTruncate)
		})
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		h    Handler
	}{
		{name: "empty include", cfg: Config{}, h: func(Line) {}},
		{name: "nil handler", cfg: Config{Include: []string{"*.log"}}, h: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.cfg, c.h)
			require.Error(t, err)
		})
	}
}

// collector gathers emitted lines in a thread-safe way.
type collector struct {
	mu    sync.Mutex
	lines []string
}

func (c *collector) handle(l Line) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, string(l.Raw))
}

func (c *collector) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

// criLine builds one full CRI stdout record for text.
func criLine(text string) string {
	return "2026-10-29T13:00:00.000000001Z stdout F " + text
}

// appendLines writes each text as a CRI line to path.
func appendLines(t *testing.T, path string, texts ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	defer f.Close()
	for _, text := range texts {
		_, err = fmt.Fprintln(f, criLine(text))
		require.NoError(t, err)
	}
}

// eventuallyHas waits until c holds exactly the raw lines for want, in order.
func eventuallyHas(t *testing.T, c *collector, want ...string) {
	t.Helper()
	wantRaw := make([]string, len(want))
	for i, w := range want {
		wantRaw[i] = criLine(w)
	}
	require.Eventually(t, func() bool {
		return assert.ObjectsAreEqual(wantRaw, c.snapshot())
	}, 3*time.Second, 20*time.Millisecond, "got %v want %v", c.snapshot(), wantRaw)
}

// eventuallyHasSet waits until c holds the raw lines for want with no loss and
// no duplicate. It ignores order, because a poll tailer does not keep order
// across a rotation boundary.
func eventuallyHasSet(t *testing.T, c *collector, want ...string) {
	t.Helper()
	wantRaw := make([]string, len(want))
	for i, w := range want {
		wantRaw[i] = criLine(w)
	}
	sort.Strings(wantRaw)
	require.Eventually(t, func() bool {
		got := c.snapshot()
		sort.Strings(got)
		return assert.ObjectsAreEqual(wantRaw, got)
	}, 5*time.Second, 20*time.Millisecond, "missing or duplicate lines: got %d want %d", len(c.snapshot()), len(wantRaw))
}

// startTailer builds and starts a tailer and stops it on cleanup.
func startTailer(t *testing.T, cfg Config) *collector {
	t.Helper()
	c := &collector{}
	tl, err := New(cfg, c.handle)
	require.NoError(t, err)
	require.NoError(t, tl.Start())
	t.Cleanup(func() { _ = tl.Stop() })
	return c
}

func TestTailerStartsAtEnd(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	appendLines(t, logPath, "old-1", "old-2")

	c := startTailer(t, Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
	})
	// Let the first poll set the offset to the end before new writes.
	time.Sleep(100 * time.Millisecond)
	appendLines(t, logPath, "new-1", "new-2")

	eventuallyHas(t, c, "new-1", "new-2")
}

func TestTailerNoLossOnRenameRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	appendLines(t, logPath, "seed")

	c := startTailer(t, Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
	})
	time.Sleep(100 * time.Millisecond)

	appendLines(t, logPath, "before-rotate")
	eventuallyHas(t, c, "before-rotate")

	// The kubelet renames the active file and the runtime opens a new one.
	require.NoError(t, os.Rename(logPath, logPath+".1"))
	appendLines(t, logPath, "after-rotate")

	eventuallyHas(t, c, "before-rotate", "after-rotate")
}

func TestTailerIgnoresCompressedRotations(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	appendLines(t, logPath, "seed")

	c := startTailer(t, Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		Exclude:      []string{"**/*.gz", "**/*.tmp"},
		PollInterval: 20 * time.Millisecond,
	})
	time.Sleep(100 * time.Millisecond)

	// The kubelet renames the active file, then compresses the older rotated
	// file to ".gz" through a ".tmp" file. The caller excludes those files, so
	// the tailer must not read them. It reads container logs, not archives.
	appendLines(t, filepath.Join(dir, "0.log.20261104-000000.gz"), "gz-garbage")
	appendLines(t, filepath.Join(dir, "0.log.20261104-000000.tmp"), "tmp-garbage")

	// A sentinel on the live file arrives after one more poll. By then the
	// tailer has also seen the .gz and .tmp files.
	appendLines(t, logPath, "live-1")
	eventuallyHas(t, c, "live-1")
}

func TestTailerNoLossOnCopytruncate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	appendLines(t, logPath, "seed")

	c := startTailer(t, Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
	})
	time.Sleep(100 * time.Millisecond)

	appendLines(t, logPath, "a-1", "a-2")
	eventuallyHas(t, c, "a-1", "a-2")

	// A copytruncate rotator copies the file, then truncates it in place. The
	// runtime keeps the same descriptor and writes new lines from offset 0.
	// With on_truncate "read_new" the tailer reads the new lines.
	require.NoError(t, os.Truncate(logPath, 0))
	appendLines(t, logPath, "b-1", "b-2")

	eventuallyHas(t, c, "a-1", "a-2", "b-1", "b-2")
}

func TestTailerRotationUnderLoad(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))

	c := startTailer(t, Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
		StartAt:      "beginning",
	})

	const total = 200
	const rotateAt = 100
	for i := range total {
		appendLines(t, logPath, fmt.Sprintf("load-%d", i))
		if i == rotateAt {
			// Rename rotation while writes continue. The runtime opens a new
			// file at the same path.
			require.NoError(t, os.Rename(logPath, logPath+".1"))
			require.NoError(t, os.WriteFile(logPath, nil, 0o600))
		}
		time.Sleep(2 * time.Millisecond)
	}

	want := make([]string, total)
	for i := range total {
		want[i] = fmt.Sprintf("load-%d", i)
	}
	eventuallyHasSet(t, c, want...)
}

func TestTailerResumesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	statePath := filepath.Join(dir, "state.json")
	appendLines(t, logPath, "seed")

	cfg := Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
		StatePath:    statePath,
	}

	first := &collector{}
	tl1, err := New(cfg, first.handle)
	require.NoError(t, err)
	require.NoError(t, tl1.Start())
	time.Sleep(100 * time.Millisecond)
	appendLines(t, logPath, "line-1")
	require.Eventually(t, func() bool { return len(first.snapshot()) == 1 },
		3*time.Second, 20*time.Millisecond)
	require.NoError(t, tl1.Stop())

	// Lines written while the tailer is down must arrive after restart, and
	// the already-read line must not repeat.
	appendLines(t, logPath, "line-2", "line-3")

	second := startTailer(t, cfg)
	eventuallyHas(t, second, "line-2", "line-3")
}

// writeRaw appends exact bytes to path without a trailing newline.
func writeRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.WriteString(s)
	require.NoError(t, err)
}

func TestTailerLineAcrossPollBoundary(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))

	c := startTailer(t, Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
		StartAt:      "beginning",
	})

	full := criLine("split-line")
	// Write the first half, let a poll run, then finish the line.
	writeRaw(t, logPath, full[:10])
	time.Sleep(60 * time.Millisecond)
	writeRaw(t, logPath, full[10:]+"\n")

	eventuallyHas(t, c, "split-line")
}
