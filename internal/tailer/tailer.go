package tailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/emit"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/matcher"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"go.opentelemetry.io/collector/component"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
)

const defaultPollInterval = 200 * time.Millisecond

// Line is one raw log line read from a file. Raw holds the line without the
// trailing newline. ReadAt is the time the agent read the line.
type Line struct {
	Raw    []byte
	ReadAt time.Time
}

// Handler receives one raw line.
type Handler func(Line)

// Config holds the tailer settings. Include is required.
type Config struct {
	// Include is the set of file globs to tail, for example
	// "/var/log/containers/*ztunnel*.log".
	Include []string
	// Exclude is an optional set of globs to skip. A caller that tails kubelet
	// container logs must exclude the rotation artifacts (".gz" and ".tmp"
	// files), because the kubelet compresses older rotated files.
	Exclude []string
	// PollInterval is the file poll period. The default is 200 ms.
	PollInterval time.Duration
	// StartAt is "end" (default) or "beginning". The agent uses end on a fresh
	// state and beginning when reopening any existing state to avoid skipping
	// available history if an offset checkpoint is missing.
	StartAt string
	// OnTruncate controls copytruncate handling. The default is "read_new".
	OnTruncate string
	// StatePath is the standalone JSON checkpoint file. When empty, the tailer
	// keeps no offsets and starts fresh on every run. It cannot be combined with
	// CheckpointStore.
	StatePath string
	// CheckpointStore optionally atomically commits staged handler events with
	// stanza's knownFiles checkpoint. Standalone callers may leave it nil.
	CheckpointStore operator.Persister
	// PersistenceError reports latched failures hidden by stanza's poll logger.
	PersistenceError func() error
	// OnFilesObserved receives paths matching the configured criteria, rather than
	// the glob patterns. The paths are a live matcher observation, not open fds.
	OnFilesObserved func([]string)
}

func (c *Config) applyDefaults() {
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.StartAt == "" {
		c.StartAt = "end"
	}
	if c.OnTruncate == "" {
		c.OnTruncate = fileconsumer.OnTruncateReadNew
	}
}

// Tailer reads CRI log files and emits each raw line to a handler.
type Tailer struct {
	mgr            *fileconsumer.Manager
	per            *filePersister
	store          operator.Persister
	persistenceErr func() error
	filesMatcher   *matcher.Matcher
	pollInterval   time.Duration
	onFiles        func([]string)
	obsCancel      context.CancelFunc
	obsWG          sync.WaitGroup
}

// New builds a tailer. It returns an error when Include is empty, the handler
// is nil, or the fileconsumer manager cannot build.
func New(cfg Config, h Handler) (*Tailer, error) {
	if len(cfg.Include) == 0 {
		return nil, errors.New("tailer: Include is required")
	}
	if h == nil {
		return nil, errors.New("tailer: Handler is required")
	}
	cfg.applyDefaults()
	if cfg.CheckpointStore != nil && cfg.StatePath != "" {
		return nil, errors.New("tailer: StatePath and CheckpointStore cannot both be set")
	}
	filesMatcher, err := matcher.New(matcher.Criteria{Include: cfg.Include, Exclude: cfg.Exclude})
	if err != nil {
		return nil, fmt.Errorf("tailer: build file matcher: %w", err)
	}

	fcCfg := fileconsumer.NewConfig()
	fcCfg.Criteria = matcher.Criteria{Include: cfg.Include, Exclude: cfg.Exclude}
	fcCfg.PollInterval = cfg.PollInterval
	fcCfg.StartAt = cfg.StartAt
	fcCfg.OnTruncate = cfg.OnTruncate
	// The agent transaction seam persists only the exact knownFiles checkpoint.
	// Never enable archive keys or partial-batch poll exits on this path.
	fcCfg.PollsToArchive = 0
	fcCfg.MaxBatches = 0
	// Emit each line as soon as it completes. The default flush period holds a
	// partial line for 500 ms, which can emit an incomplete record.
	fcCfg.FlushPeriod = 0
	fcCfg.IncludeFileName = false

	cb := emit.Callback(func(_ context.Context, tokens [][]byte, _ map[string]any, _ int64, _ []int64) error {
		readAt := time.Now()
		for _, tok := range tokens {
			// fileconsumer reuses the token buffer. Copy each token before the
			// handler keeps it.
			h(Line{Raw: append([]byte(nil), tok...), ReadAt: readAt})
		}
		return nil
	})

	mgr, err := fcCfg.Build(
		component.TelemetrySettings{
			Logger:         zap.NewNop(),
			TracerProvider: tracenoop.NewTracerProvider(),
			MeterProvider:  metricnoop.NewMeterProvider(),
		},
		cb,
	)
	if err != nil {
		return nil, fmt.Errorf("tailer: build fileconsumer: %w", err)
	}

	t := &Tailer{
		mgr: mgr, store: cfg.CheckpointStore, persistenceErr: cfg.PersistenceError,
		filesMatcher: filesMatcher, pollInterval: cfg.PollInterval, onFiles: cfg.OnFilesObserved,
	}
	if cfg.StatePath != "" {
		per, persErr := newFilePersister(cfg.StatePath)
		if persErr != nil {
			return nil, fmt.Errorf("tailer: load checkpoints: %w", persErr)
		}
		t.per = per
	}
	return t, nil
}

// persister returns the checkpoint store for the manager, or nil when the
// tailer keeps no offsets. It must not return a typed-nil pointer, because the
// manager treats any non-nil interface as a real store.
func (t *Tailer) persister() operator.Persister {
	if t.store != nil {
		return t.store
	}
	if t.per == nil {
		return nil
	}
	return t.per
}

// Start begins the poll loop. The manager polls on the interval until Stop.
func (t *Tailer) Start() error {
	err := t.mgr.Start(t.persister())
	if err == nil {
		t.startFileObserver()
		return nil
	}
	// An injected transaction store must fail closed on malformed nested offsets.
	if t.store != nil {
		return fmt.Errorf("tailer: start: %w", err)
	}
	// Without a checkpoint store the error cannot be a bad payload.
	if t.per == nil {
		return fmt.Errorf("tailer: start: %w", err)
	}
	// The checkpoint file passed the outer JSON decode, but fileconsumer
	// rejects its offset payload. Drop the bad offsets and start fresh, so a
	// corrupt checkpoint does not stop the agent on every restart.
	slog.Default().Warn("Dropped a malformed checkpoint payload; started fresh",
		"path", t.per.path, "err", err)
	if resetErr := t.per.reset(); resetErr != nil {
		return fmt.Errorf("tailer: reset checkpoints: %w", resetErr)
	}
	// A second failure, now with an empty store, is a genuine error.
	if retryErr := t.mgr.Start(t.per); retryErr != nil {
		return fmt.Errorf("tailer: start: %w", retryErr)
	}
	t.startFileObserver()
	return nil
}

func (t *Tailer) startFileObserver() {
	if t.onFiles == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.obsCancel = cancel
	t.obsWG.Go(func() {
		ticker := time.NewTicker(t.pollInterval)
		defer ticker.Stop()
		observe := func() {
			paths, _ := t.filesMatcher.MatchFiles()
			sort.Strings(paths)
			t.onFiles(append([]string(nil), paths...))
		}
		observe()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				observe()
			}
		}
	})
}

// Err reports durability errors that the stanza manager logs but suppresses.
func (t *Tailer) Err() error {
	if t.persistenceErr == nil {
		return nil
	}
	return t.persistenceErr()
}

// Stop ends the poll loop and flushes the final offsets.
func (t *Tailer) Stop() error {
	stopErr := t.mgr.Stop()
	if t.obsCancel != nil {
		t.obsCancel()
		t.obsWG.Wait()
	}
	if stopErr != nil {
		return fmt.Errorf("tailer: stop: %w", stopErr)
	}
	if err := t.Err(); err != nil {
		return fmt.Errorf("tailer: persistence: %w", err)
	}
	return nil
}
