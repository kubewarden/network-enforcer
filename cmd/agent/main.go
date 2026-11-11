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

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/tailer"
	"github.com/kubewarden/network-enforcer/internal/tlsutil"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Include retained rotations so their unread tails can be drained while running.
	glob := flag.String("log-glob", "/var/log/pods/istio-system_ztunnel*/*/*.log*",
		"glob for the container log files to tail")
	poll := flag.Duration("poll-interval", 200*time.Millisecond,
		"file poll period")
	grpcTLSEnabled := flag.Bool("grpc-mtls-enabled", true,
		"enable mutual TLS between the agent server and clients")
	grpcCertDir := flag.String("grpc-mtls-cert-dir", "",
		"path to the directory holding the agent certificate, key and CA")
	flag.Parse()

	// Check the mounted material before the agent serves anything.
	// ref: https://github.com/kubewarden/network-enforcer/issues/641
	if err := validateGRPCTLS(*grpcTLSEnabled, *grpcCertDir); err != nil {
		logger.Error("Invalid gRPC mTLS material", "err", err)
		os.Exit(1)
	}

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
	if err := runAgent(ctx, cfg, agentbuffer.New(), logger); err != nil {
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

// validateGRPCTLS checks the certificate directory the agent serves with.
// Disabled mode skips the check and serves in plaintext. Use it only for
// local development.
func validateGRPCTLS(enabled bool, certDir string) error {
	if !enabled {
		return nil
	}
	return tlsutil.ValidateCertDir(certDir)
}
