package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	otellog "go.opentelemetry.io/otel/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/network-enforcer/internal/certsource"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	"github.com/kubewarden/network-enforcer/internal/violation"
)

type CiliumScraperConfig struct {
	client.Client

	Logger               *slog.Logger
	Endpoint             string
	EnqueueLearningEvent LearningEnqueueFunc
	ViolationOtelLogger  otellog.Logger
	ViolationBuffer      *ringbuf.Buffer[violation.Observation]
	FlowDumperBuffer     *ringbuf.Buffer[json.RawMessage]
	// A nil CertSource means the hop runs in plaintext.
	CertSource    certsource.Source
	TLSServerName string
}

type CiliumScraper struct {
	CiliumScraperConfig
}

// NewCiliumScraper creates a Cilium learning scraper.
func NewCiliumScraper(conf CiliumScraperConfig) *CiliumScraper {
	return &CiliumScraper{CiliumScraperConfig: conf}
}

// Relay's certificate is always issued for *.hubble-relay.cilium.io, so the endpoint host is only a fallback.
// Material is re-read on every call, so rotation is picked up on the next reconnect.
func (s *CiliumScraper) transportCredentials(ctx context.Context) (credentials.TransportCredentials, error) {
	if s.CertSource == nil {
		s.Logger.WarnContext(ctx, "Connecting to Hubble Relay without TLS")
		return insecure.NewCredentials(), nil
	}

	serverName, err := resolveTLSServerName(s.Endpoint, s.TLSServerName, "Hubble Relay")
	if err != nil {
		return nil, err
	}

	ca, cert, key, err := s.CertSource.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain TLS material for Hubble Relay: %w", err)
	}
	creds, err := tlsutil.ClientCredentialsFromPEM(ca, cert, key, serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS credentials for Hubble Relay: %w", err)
	}
	s.Logger.InfoContext(ctx, "Using TLS credentials for Hubble Relay connection", "serverName", serverName)
	return creds, nil
}

func (s *CiliumScraper) dialOptions(ctx context.Context) ([]grpc.DialOption, error) {
	creds, err := s.transportCredentials(ctx)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	// gRPC overwrites tls.Config.ServerName with the channel authority, so the override must be the authority.
	if s.CertSource != nil && s.TLSServerName != "" {
		opts = append(opts, grpc.WithAuthority(s.TLSServerName))
	}
	return opts, nil
}

func (s *CiliumScraper) newHubbleClient(ctx context.Context) (hubbleObserver.ObserverClient, *grpc.ClientConn, error) {
	opts, err := s.dialOptions(ctx)
	if err != nil {
		return nil, nil, err
	}

	conn, err := grpc.NewClient(s.Endpoint, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to Hubble: %w", err)
	}

	client := hubbleObserver.NewObserverClient(conn)
	return client, conn, nil
}

func (s *CiliumScraper) Start(ctx context.Context) error {
	s.Logger.InfoContext(ctx, "Starting Cilium scraper")
	return runStreamWithReconnect(ctx, s.Logger, "Cilium", s.stream)
}

func (s *CiliumScraper) stream(ctx context.Context, successfulConnection *bool) error {
	*successfulConnection = false
	client, conn, err := s.newHubbleClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Hubble client: %w", err)
	}
	defer conn.Close()

	req := &hubbleObserver.GetFlowsRequest{
		Number:    0,
		Follow:    true,
		Whitelist: []*flowpb.FlowFilter{},
	}
	innerClient, err := client.GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get flows from Hubble: %w", err)
	}

	for {
		flow, recvErr := innerClient.Recv()
		if recvErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("error receiving flow from Hubble: %w", recvErr)
		}
		*successfulConnection = true
		dumpFlow(ctx, s.Logger, s.FlowDumperBuffer, flow)
		result := s.processFlow(ctx, flow)
		switch result.outcome {
		case processFlowOutcomeSkip:
			// nothing; continue
		case processFlowOutcomeError:
			s.Logger.ErrorContext(ctx, "Failed to process flow",
				"flow", flow,
				"error", result.err,
			)
		case processFlowOutcomeEnqueue:
			if !s.EnqueueLearningEvent(result.event) {
				// todo!: we can consider some rate limiting here
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
				"flow", flow,
				"error", "unknown flow outcome",
			)
		}
	}
}
