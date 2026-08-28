package scraper

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	"github.com/rancher-sandbox/network-enforcer/internal/ringbuf"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CiliumScraperConfig struct {
	client.Client

	Logger               *slog.Logger
	Endpoint             string
	EnqueueLearningEvent LearningEnqueueFunc
	ViolationBuffer      *ringbuf.Buffer[violation.Observation]
	FlowDumperBuffer     *ringbuf.Buffer[json.RawMessage]
}

type CiliumScraper struct {
	CiliumScraperConfig
}

// NewCiliumScraper creates a Cilium learning scraper.
func NewCiliumScraper(conf CiliumScraperConfig) *CiliumScraper {
	return &CiliumScraper{CiliumScraperConfig: conf}
}

func (s *CiliumScraper) newHubbleClient() (hubbleObserver.ObserverClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		s.Endpoint,
		// todo!: support TLS with hubble-relay
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

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
	client, conn, err := s.newHubbleClient()
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
			if s.ViolationBuffer.Record(result.observation) {
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
