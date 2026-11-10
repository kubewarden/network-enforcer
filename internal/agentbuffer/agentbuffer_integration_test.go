package agentbuffer

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

func TestScrapeEventsOverGRPCDrainsOnce(t *testing.T) {
	buffer := New()
	buffer.RecordLine(policyLine("first"))
	buffer.RecordLine(policyLine("second"))
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentServiceServer(server, buffer)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		require.NoError(t, listener.Close())
		require.NoError(t, <-done)
	})

	conn, err := grpc.NewClient("passthrough:///agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	client := agentv1.NewAgentServiceClient(conn)
	before, err := client.GetStatus(t.Context(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(2), before.GetBufferedEvents())
	response, err := client.ScrapeEvents(t.Context(), &agentv1.ScrapeEventsRequest{})
	require.NoError(t, err)
	require.Len(t, response.GetEvents(), 2)
	require.Equal(t, "second", response.GetEvents()[0].GetPolicy().GetPolicy())
	require.Equal(t, "first", response.GetEvents()[1].GetPolicy().GetPolicy())
	response, err = client.ScrapeEvents(t.Context(), &agentv1.ScrapeEventsRequest{})
	require.NoError(t, err)
	require.Empty(t, response.GetEvents())
	after, err := client.GetStatus(t.Context(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Zero(t, after.GetBufferedEvents())
	require.Equal(t, before.GetReceivedEvents(), after.GetReceivedEvents())
}
