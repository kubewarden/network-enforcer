package tailer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/emit"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/fileconsumer/matcher"
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
	// PollInterval is the file poll period. The default is 200 ms.
	PollInterval time.Duration
	// StartAt is "end" (default) or "beginning". The agent uses "end", so it
	// does not replay history on the first run.
	StartAt string
	// OnTruncate controls copytruncate handling. The default is "read_new".
	OnTruncate string
	// StatePath is the JSON checkpoint file. When empty, the tailer keeps no
	// offsets and starts fresh on every run.
	StatePath string
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
	mgr *fileconsumer.Manager
	per *filePersister
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

	fcCfg := fileconsumer.NewConfig()
	fcCfg.Criteria = matcher.Criteria{Include: cfg.Include}
	fcCfg.PollInterval = cfg.PollInterval
	fcCfg.StartAt = cfg.StartAt
	fcCfg.OnTruncate = cfg.OnTruncate
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

	t := &Tailer{mgr: mgr}
	if cfg.StatePath != "" {
		per, persErr := newFilePersister(cfg.StatePath)
		if persErr != nil {
			return nil, fmt.Errorf("tailer: load checkpoints: %w", persErr)
		}
		t.per = per
	}
	return t, nil
}

// Start begins the poll loop. The manager polls on the interval until Stop.
func (t *Tailer) Start() error {
	var err error
	if t.per != nil {
		err = t.mgr.Start(t.per)
	} else {
		err = t.mgr.Start(nil)
	}
	if err != nil {
		return fmt.Errorf("tailer: start: %w", err)
	}
	return nil
}

// Stop ends the poll loop and flushes the final offsets.
func (t *Tailer) Stop() error {
	if err := t.mgr.Stop(); err != nil {
		return fmt.Errorf("tailer: stop: %w", err)
	}
	return nil
}
