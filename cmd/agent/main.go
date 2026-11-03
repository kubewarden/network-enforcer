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

	glob := flag.String("log-glob", "/var/log/containers/*ztunnel*.log",
		"glob for the container log files to tail")
	poll := flag.Duration("poll-interval", 200*time.Millisecond,
		"file poll period")
	statePath := flag.String("checkpoint-file", "",
		"path to the JSON checkpoint file; empty disables persistence")
	flag.Parse()

	cfg := tailer.Config{
		Include:      []string{*glob},
		PollInterval: *poll,
		StatePath:    *statePath,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Starting agent")
	exitCode := 0
	if err := run(ctx, cfg, printLine(logger), logger); err != nil {
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

// printLine returns a handler that prints each line through the logger.
func printLine(logger *slog.Logger) tailer.Handler {
	return func(l tailer.Line) {
		logger.Info("Flow log", "line", string(l.Raw))
	}
}
