/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubewarden/network-enforcer/internal/tailer"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Tail the pod log directory, not the "/var/log/containers" symlinks. The
	// symlinks only point to the active file, so a file that the kubelet rotates
	// while the agent is down would be missed on restart. The pod directory also
	// holds the retained rotated files, so recovery can drain their unread tail.
	// The default matches the ztunnel pod in the "istio-system" namespace. Pass
	// -log-glob to tail a different namespace, pod or path.
	glob := flag.String("log-glob", "/var/log/pods/istio-system_ztunnel*/*/*.log*",
		"glob for the container log files to tail")
	poll := flag.Duration("poll-interval", 200*time.Millisecond,
		"file poll period")
	stateDir := flag.String("state-dir", "/var/lib/network-enforcer/agent",
		"directory for the durable event buffer and tailer checkpoint")
	flag.Parse()

	cfg := tailer.Config{
		Include: []string{*glob},
		// Skip the kubelet rotation artifacts. The kubelet compresses older
		// rotated files to ".gz" through a ".tmp" file. Those files are not
		// live container logs.
		Exclude:      []string{"**/*.gz", "**/*.tmp"},
		PollInterval: *poll,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Starting agent")
	exitCode := 0
	if err := runAgent(ctx, cfg, *stateDir, logger); err != nil {
		logger.Error("Agent failed", "err", err)
		exitCode = 1
	}
	logger.Info("Stopped agent")
	stop()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// run starts the tailer, blocks until the context ends, then stops the tailer.
func run(ctx context.Context, cfg tailer.Config, h tailer.Handler, logger *slog.Logger) error {
	t, err := tailer.New(cfg, h)
	if err != nil {
		return err
	}
	if startErr := t.Start(); startErr != nil {
		return startErr
	}
	logger.InfoContext(ctx, "Started tailer", "glob", cfg.Include)
	<-ctx.Done()
	logger.InfoContext(ctx, "Stopping tailer")
	return t.Stop()
}
