package main

import (
	"context"
	"log/slog"

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/tailer"
)

// Start the tailer before opening the gRPC port: kubelet probes that port for
// readiness. No matching files or traffic are required for an idle node.
func runAgent(
	ctx context.Context,
	cfg tailer.Config,
	buffer *agentbuffer.Buffer,
	serve func(context.Context) error,
	logger *slog.Logger,
) error {
	cfg.StartAt = "end"
	cfg.StatePath = ""
	cfg.OnFilesObserved = buffer.SetCurrentLogFiles
	return run(ctx, cfg, func(line tailer.Line) { buffer.RecordLine(line.Raw) }, logger, serve)
}
