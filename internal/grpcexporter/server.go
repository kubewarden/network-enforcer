// Package grpcexporter serves the agent event buffer over gRPC and dials it
// from the controller. The agent is the server; the controller is the client.
package grpcexporter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

// gracefulStopTimeout bounds the wait for in-flight RPCs on shutdown before the
// server is forced to stop.
const gracefulStopTimeout = 5 * time.Second

// ServerConfig configures the agent-hop gRPC server.
type ServerConfig struct {
	// Port is the TCP port the server listens on.
	Port int
	// MTLSEnabled requires mutual TLS. Disable it only for local development.
	MTLSEnabled bool
	// CertDirPath holds tls.crt, tls.key, and ca.crt when MTLSEnabled is true.
	CertDirPath string
	// ExpectedClientSAN pins the controller identity the client must present.
	// Empty keeps chain-only verification.
	ExpectedClientSAN string
}

// Server serves the agent's [agentv1.AgentServiceServer] over gRPC.
type Server struct {
	conf    ServerConfig
	service agentv1.AgentServiceServer
	logger  *slog.Logger
}

// NewServer returns a Server that serves service with conf.
func NewServer(conf ServerConfig, service agentv1.AgentServiceServer, logger *slog.Logger) (*Server, error) {
	if service == nil {
		return nil, errors.New("agent service is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	return &Server{conf: conf, service: service, logger: logger}, nil
}

// Start listens on the configured port and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	addr := fmt.Sprintf(":%d", s.conf.Port)
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	return s.Serve(ctx, listener)
}

// Serve serves on listener until ctx is cancelled. It stops gracefully, then
// forces a stop if in-flight RPCs exceed [gracefulStopTimeout].
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	opts, err := s.serverOptions()
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(opts...)
	agentv1.RegisterAgentServiceServer(grpcServer, s.service)
	s.logger.InfoContext(ctx, "Starting agent gRPC server",
		"addr", listener.Addr().String(), "mTLS", s.conf.MTLSEnabled)

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- grpcServer.Serve(listener) }()

	select {
	case err = <-serveErrCh:
		if err != nil {
			return fmt.Errorf("agent gRPC server stopped: %w", err)
		}
		return nil
	case <-ctx.Done():
		s.stop(ctx, grpcServer)
		return nil
	}
}

func (s *Server) stop(ctx context.Context, grpcServer *grpc.Server) {
	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(gracefulStopTimeout):
		s.logger.WarnContext(ctx, "Agent gRPC graceful stop timed out; forcing stop",
			"timeout", gracefulStopTimeout.String())
		grpcServer.Stop()
	}
}

func (s *Server) serverOptions() ([]grpc.ServerOption, error) {
	// ConnectionTimeout bounds how long a new connection can stay in the
	// handshake or HTTP/2 preface. Both GracefulStop and Stop wait for these
	// connections. Without a bound, a client that opens a socket and sends
	// nothing keeps shutdown blocked past the pod termination grace period. The
	// bound applies to the TLS handshake and the plaintext preface.
	opts := []grpc.ServerOption{grpc.ConnectionTimeout(gracefulStopTimeout)}

	if !s.conf.MTLSEnabled {
		return opts, nil
	}
	creds, err := tlsutil.ServerCredentials(
		s.conf.CertDirPath,
		tlsutil.WithExpectedClientSAN(s.conf.ExpectedClientSAN),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load agent server credentials: %w", err)
	}
	return append(opts, grpc.Creds(creds)), nil
}
