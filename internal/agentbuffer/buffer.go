package agentbuffer

import (
	"context"
	"slices"
	"sync"

	"google.golang.org/grpc/status"

	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

const MaxBufferEntries = 10_000

type Buffer struct {
	agentv1.UnimplementedAgentServiceServer

	mu             sync.Mutex
	events         *ringbuf.Buffer[*agentv1.Event]
	bufferedEvents uint64
	receivedEvents uint64
	droppedEvents  uint64
	currentLogs    []string
}

func New() *Buffer {
	return &Buffer{events: ringbuf.NewWithSize[*agentv1.Event](MaxBufferEntries)}
}

func (b *Buffer) RecordLine(raw []byte) bool {
	event, classified := parseLine(raw)
	b.mu.Lock()
	defer b.mu.Unlock()

	b.receivedEvents++
	if !classified {
		return false
	}
	if b.events.Record(event) {
		b.droppedEvents++
		return true
	}
	b.bufferedEvents++
	return false
}

func (b *Buffer) ScrapeEvents(
	ctx context.Context,
	_ *agentv1.ScrapeEventsRequest,
) (*agentv1.ScrapeEventsResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	events := b.events.Drain()
	b.bufferedEvents = 0
	return &agentv1.ScrapeEventsResponse{Events: events}, nil
}

func (b *Buffer) GetStatus(_ context.Context, _ *agentv1.GetStatusRequest) (*agentv1.GetStatusResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return &agentv1.GetStatusResponse{
		BufferedEvents:  b.bufferedEvents,
		MaxEvents:       MaxBufferEntries,
		DroppedEvents:   b.droppedEvents,
		ReceivedEvents:  b.receivedEvents,
		CurrentLogFiles: slices.Clone(b.currentLogs),
	}, nil
}

func (b *Buffer) SetCurrentLogFiles(paths []string) {
	paths = slices.Clone(paths)
	slices.Sort(paths)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.currentLogs = slices.Compact(paths)
}

var _ agentv1.AgentServiceServer = (*Buffer)(nil)
