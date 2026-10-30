package events_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"

	"github.com/kubewarden/network-enforcer/internal/events"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		wantErr  bool
	}{
		{name: "empty protocol means grpc", protocol: ""},
		{name: "grpc", protocol: "grpc"},
		{name: "http/protobuf", protocol: "http/protobuf"},
		{name: "unsupported protocol", protocol: "foo", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, shutdown, err := events.Init(t.Context(), tt.protocol)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, logger)
			require.NoError(t, shutdown(context.Background()))
		})
	}
}

type countingLogsServer struct {
	collogspb.UnimplementedLogsServiceServer

	requests atomic.Int32
}

func (s *countingLogsServer) Export(
	_ context.Context,
	_ *collogspb.ExportLogsServiceRequest,
) (*collogspb.ExportLogsServiceResponse, error) {
	s.requests.Add(1)
	return &collogspb.ExportLogsServiceResponse{}, nil
}

// TestInitExportsToEndpointFromEnvironment checks that the exporter reads
// the endpoint from OTEL_EXPORTER_OTLP_ENDPOINT,
// and that an http:// endpoint means a plaintext connection.
func TestInitExportsToEndpointFromEnvironment(t *testing.T) {
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &countingLogsServer{}
	grpcServer := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+lis.Addr().String())

	logger, shutdown, err := events.Init(t.Context(), "")
	require.NoError(t, err)

	var record otellog.Record
	record.SetBody(attribute.StringValue("policy_violation_acknowledged"))
	logger.Emit(t.Context(), record)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, shutdown(shutdownCtx))

	require.Equal(t, int32(1), srv.requests.Load())
}
