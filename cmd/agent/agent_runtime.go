package main

import (
	"context"
	"log/slog"
	"net"

	"golang.org/x/sync/errgroup"

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/grpcexporter"
	"github.com/kubewarden/network-enforcer/internal/tailer"
)

// runAgent tails the matching log files into the buffer. When server and
// listener are both set, it also serves the AgentService next to the tailer.
// The first failure stops the other task and returns. See RFC 0006.
func runAgent(
	ctx context.Context,
	cfg tailer.Config,
	buffer *agentbuffer.Buffer,
	server *grpcexporter.Server,
	listener net.Listener,
	logger *slog.Logger,
) error {
	cfg.StartAt = "end"
	cfg.StatePath = ""
	cfg.OnFilesObserved = buffer.SetCurrentLogFiles

	group, groupCtx := errgroup.WithContext(ctx)
	if server != nil && listener != nil {
		group.Go(func() error {
			return server.Serve(groupCtx, listener)
		})
	}
	group.Go(func() error {
		return run(groupCtx, cfg, func(line tailer.Line) {
			buffer.RecordLine(line.Raw)
		}, logger)
	})
	return group.Wait()
}
