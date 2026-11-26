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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/grpcexporter"
	"github.com/kubewarden/network-enforcer/internal/tailer"
	"github.com/kubewarden/network-enforcer/internal/tlsutil"
)

const (
	defaultLogGlob          = "/var/log/pods/istio-system_ztunnel-*/{ztunnel,istio-proxy}/*.log"
	defaultPollInterval     = 200 * time.Millisecond
	defaultGRPCPort         = 50052
	invalidArgumentExitCode = 2
)

type agentOptions struct {
	logGlob               string
	pollInterval          time.Duration
	grpcPort              int
	grpcTLSEnabled        bool
	grpcCertDir           string
	grpcExpectedClientSAN string
}

func parseAgentArgs(args []string) (agentOptions, error) {
	if err := validateAgentArgumentBoundary(args); err != nil {
		return agentOptions{}, err
	}
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	var options agentOptions
	flags.StringVar(&options.logGlob, "log-glob", defaultLogGlob, "glob for the container log files to tail")
	flags.DurationVar(&options.pollInterval, "poll-interval", defaultPollInterval, "file poll period")
	flags.IntVar(&options.grpcPort, "grpc-port", defaultGRPCPort, "TCP port the agent gRPC server listens on")
	flags.BoolVar(
		&options.grpcTLSEnabled,
		"grpc-mtls-enabled",
		true,
		"enable mutual TLS between the agent server and clients",
	)
	flags.StringVar(
		&options.grpcCertDir,
		"grpc-mtls-cert-dir",
		"",
		"path to the directory holding the agent certificate, key and CA",
	)
	flags.StringVar(
		&options.grpcExpectedClientSAN,
		"grpc-expected-client-san",
		"",
		"DNS SAN the controller client must present; empty keeps chain-only verification",
	)
	if err := flags.Parse(args); err != nil {
		return agentOptions{}, err
	}
	if flags.NArg() != 0 {
		return agentOptions{}, fmt.Errorf("unexpected positional arguments: %q", flags.Args())
	}
	return options, nil
}

func validateAgentArgumentBoundary(args []string) error {
	valueFlags := map[string]struct{}{
		"grpc-port":                {},
		"grpc-mtls-cert-dir":       {},
		"grpc-expected-client-san": {},
		"log-glob":                 {},
		"poll-interval":            {},
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || arg == "-h" || arg == "-help" || arg == "--help" {
			return nil
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		nameValue := strings.TrimLeft(arg, "-")
		name, _, hasValue := strings.Cut(nameValue, "=")
		if hasValue {
			continue
		}
		if _, takesValue := valueFlags[name]; !takesValue || i+1 == len(args) {
			continue
		}
		if strings.HasPrefix(args[i+1], "-") {
			return fmt.Errorf("flag %s must use an equals value before another flag", arg)
		}
		i++
	}
	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	options, err := parseAgentArgs(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		logger.Error("Invalid agent arguments", "err", err)
		os.Exit(invalidArgumentExitCode)
	}

	// Check the mounted material before the agent serves anything.
	// ref: https://github.com/kubewarden/network-enforcer/issues/641
	if tlsErr := validateGRPCTLS(options.grpcTLSEnabled, options.grpcCertDir); tlsErr != nil {
		logger.Error("Invalid gRPC mTLS material", "err", tlsErr)
		os.Exit(1)
	}

	cfg := tailer.Config{
		Include: []string{options.logGlob},
		// Skip the kubelet rotation artifacts. The kubelet compresses older
		// rotated files to ".gz" through a ".tmp" file. Those files are not
		// live container logs.
		Exclude:      []string{"**/*.gz", "**/*.tmp"},
		PollInterval: options.pollInterval,
	}

	buffer := agentbuffer.New()
	server, err := grpcexporter.NewServer(grpcexporter.ServerConfig{
		Port:              options.grpcPort,
		MTLSEnabled:       options.grpcTLSEnabled,
		CertDirPath:       options.grpcCertDir,
		ExpectedClientSAN: options.grpcExpectedClientSAN,
	}, buffer, logger)
	if err != nil {
		logger.Error("Failed to build agent gRPC server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Starting agent")
	exitCode := 0
	if runErr := runAgent(ctx, cfg, buffer, server.Start, logger); runErr != nil {
		logger.Error("Agent failed", "err", runErr)
		exitCode = 1
	}
	logger.Info("Stopped agent")
	stop()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// run keeps the tailer running for the lifetime of the server.
func run(
	ctx context.Context,
	cfg tailer.Config,
	h tailer.Handler,
	logger *slog.Logger,
	serve func(context.Context) error,
) error {
	t, err := tailer.New(cfg, h)
	if err != nil {
		return err
	}
	if startErr := t.Start(); startErr != nil {
		return startErr
	}
	logger.InfoContext(ctx, "Started tailer", "glob", cfg.Include)
	err = serve(ctx)
	logger.InfoContext(ctx, "Stopping tailer")
	return errors.Join(err, t.Stop())
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
