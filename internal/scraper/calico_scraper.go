package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	otellog "go.opentelemetry.io/otel/log"
	"google.golang.org/grpc"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/network-enforcer/internal/certsource"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	pb "github.com/kubewarden/network-enforcer/internal/scraper/goldmane"
	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	"github.com/kubewarden/network-enforcer/internal/violation"
)

const (
	calicoAggregationInterval = 15
)

type CalicoScraperConfig struct {
	client.Client

	Endpoint             string
	EnqueueLearningEvent LearningEnqueueFunc
	Logger               *slog.Logger
	ViolationOtelLogger  otellog.Logger
	ViolationBuffer      *ringbuf.Buffer[violation.Observation]
	FlowDumperBuffer     *ringbuf.Buffer[json.RawMessage]
	// CertSource supplies Goldmane mTLS material.
	// Required; Goldmane rejects plaintext connections.
	// Material is re-read on every dial so CA rotation is picked up on reconnect.
	CertSource    certsource.Source
	TLSServerName string
}

type CalicoScraper struct {
	CalicoScraperConfig
}

func NewCalicoScraper(conf CalicoScraperConfig) *CalicoScraper {
	return &CalicoScraper{CalicoScraperConfig: conf}
}

func (s *CalicoScraper) Start(ctx context.Context) error {
	defer s.Logger.InfoContext(ctx, "calico scraper has stopped")
	s.Logger.InfoContext(ctx, "Starting Calico scraper")
	return runStreamWithReconnect(ctx, s.Logger, "Calico", s.stream)
}

// TLSServerName overrides the endpoint host for SNI/authority when set.
// Material is re-read on every call, so rotation is picked up on the next reconnect.
func (s *CalicoScraper) dialOptions(ctx context.Context) ([]grpc.DialOption, error) {
	if s.CertSource == nil {
		return nil, errors.New("goldmane requires TLS credentials; set --provider-tls-mode=existingSecret or issuer")
	}
	serverName, err := resolveTLSServerName(s.Endpoint, s.TLSServerName, "Goldmane")
	if err != nil {
		return nil, err
	}
	caPEM, certPEM, keyPEM, err := s.CertSource.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS credentials for Goldmane: %w", err)
	}
	creds, err := tlsutil.ClientCredentialsFromPEM(caPEM, certPEM, keyPEM, serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS credentials for Goldmane: %w", err)
	}
	s.Logger.InfoContext(ctx, "Using TLS credentials for Goldmane connection", "serverName", serverName)

	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	// gRPC overwrites tls.Config.ServerName with the channel authority, so the override must be the authority.
	if s.TLSServerName != "" {
		opts = append(opts, grpc.WithAuthority(s.TLSServerName))
	}
	return opts, nil
}

func (s *CalicoScraper) newGoldmaneClient(ctx context.Context) (*grpc.ClientConn, error) {
	opts, err := s.dialOptions(ctx)
	if err != nil {
		return nil, err
	}
	conn, connErr := grpc.NewClient(s.Endpoint, opts...)
	if connErr != nil {
		return nil, fmt.Errorf("failed to connect to Goldmane: %w", connErr)
	}
	return conn, nil
}

func (s *CalicoScraper) stream(ctx context.Context, successfulConnection *bool) error {
	*successfulConnection = false
	conn, err := s.newGoldmaneClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Goldmane client: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			s.Logger.WarnContext(ctx, "Failed to close Goldmane connection", "error", closeErr)
		}
	}()

	req := &pb.FlowStreamRequest{
		StartTimeGte: 0,
		Filter: &pb.Filter{
			Actions: []pb.Action{pb.Action_Allow, pb.Action_Deny},
		},
		AggregationInterval: calicoAggregationInterval,
	}

	s.Logger.InfoContext(ctx, "Starting to watch Calico flows from Goldmane")
	innerClient, err := pb.NewFlowsClient(conn).Stream(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to stream flows from Goldmane: %w", err)
	}

	for {
		flowResult, recvErr := innerClient.Recv()
		if recvErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("error receiving flow from Goldmane: %w", recvErr)
		}
		*successfulConnection = true
		dumpFlow(ctx, s.Logger, s.FlowDumperBuffer, flowResult)

		result := resolveParsedFlow(ctx, s.resolve, bindResolveDenyingPolicy(s.Client), parseCalicoFlow(flowResult))
		switch result.outcome {
		case processFlowOutcomeSkip:
			// nothing; continue
		case processFlowOutcomeError:
			s.Logger.ErrorContext(ctx, "Failed to process flow",
				"flow", flowResult,
				"error", result.err,
			)
		case processFlowOutcomeEnqueue:
			if !s.EnqueueLearningEvent(result.event) {
				s.Logger.WarnContext(ctx, "Failed to enqueue learning event, channel is full")
			}
		case processFlowOutcomeViolation:
			s.Logger.InfoContext(ctx, "Received violation", "violation", result.observation)
			violation.EmitOtelLog(ctx, s.ViolationOtelLogger, result.observation)
			if dropped := s.ViolationBuffer.Record(result.observation); dropped {
				s.Logger.WarnContext(ctx, "Violation buffer is full, dropped the oldest violation")
			}
		default:
			s.Logger.ErrorContext(ctx, "Failed to process flow",
				"flow", flowResult,
				"error", "unknown flow outcome",
			)
		}
	}
}
