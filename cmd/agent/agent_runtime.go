package main

import (
	"context"
	"log/slog"

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/tailer"
)

func runAgent(ctx context.Context, cfg tailer.Config, buffer *agentbuffer.Buffer, logger *slog.Logger) error {
	cfg.StartAt = "end"
	cfg.StatePath = ""
	cfg.OnFilesObserved = buffer.SetCurrentLogFiles
	return run(ctx, cfg, func(line tailer.Line) {
		buffer.RecordLine(line.Raw)
	}, logger)
}
