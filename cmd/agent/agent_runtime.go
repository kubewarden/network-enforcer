package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/tailer"
)

// runAgent owns one durable buffer/tailer pair. A recovered state always starts
// at the beginning so absent or empty offsets cannot skip available log history.
func runAgent(ctx context.Context, cfg tailer.Config, stateDir string, logger *slog.Logger) (result error) {
	buffer, recovered, err := agentbuffer.Open(stateDir, agentbuffer.Config{})
	if err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, buffer.Close())
	}()
	if recovered {
		cfg.StartAt = "beginning"
	} else {
		cfg.StartAt = "end"
	}
	cfg.CheckpointStore = buffer
	cfg.PersistenceError = buffer.Err
	cfg.OnFilesObserved = buffer.SetCurrentLogFiles

	t, err := tailer.New(cfg, func(line tailer.Line) {
		buffer.StageLine(line.Raw, line.ReadAt)
	})
	if err != nil {
		return err
	}
	if startErr := t.Start(); startErr != nil {
		return startErr
	}
	logger.InfoContext(ctx, "Started agent tailer", "glob", cfg.Include, "stateDir", stateDir, "recovered", recovered)
	defer func() {
		result = errors.Join(result, t.Stop())
	}()

	housekeeping := time.NewTicker(time.Second)
	defer housekeeping.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.InfoContext(ctx, "Stopping agent tailer")
			return nil
		case <-housekeeping.C:
			if sweepErr := buffer.Sweep(); sweepErr != nil {
				return sweepErr
			}
			if persistenceErr := t.Err(); persistenceErr != nil {
				return persistenceErr
			}
		}
	}
}
