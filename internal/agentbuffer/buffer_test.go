package agentbuffer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

func policyLine(policy string) []byte {
	return []byte(fmt.Sprintf(
		`2000-01-01T00:00:00Z stdout F {"message":"deny policy match","policy":%q,"proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}}`,
		policy,
	))
}

func scrape(t *testing.T, buffer *Buffer) []*agentv1.Event {
	t.Helper()
	response, err := buffer.ScrapeEvents(t.Context(), &agentv1.ScrapeEventsRequest{})
	require.NoError(t, err)
	return response.GetEvents()
}

func bufferStatus(t *testing.T, buffer *Buffer) *agentv1.GetStatusResponse {
	t.Helper()
	response, err := buffer.GetStatus(t.Context(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	return response
}

func TestScrapeDrainsNewestFirst(t *testing.T) {
	buffer := New()
	require.Empty(t, scrape(t, buffer))
	for _, policy := range []string{"first", "second", "third"} {
		require.False(t, buffer.RecordLine(policyLine(policy)))
	}

	before := bufferStatus(t, buffer)
	require.Equal(t, uint64(3), before.GetBufferedEvents())
	require.Equal(t, uint64(MaxBufferEntries), before.GetMaxEvents())
	require.True(t, proto.Equal(before, bufferStatus(t, buffer)))

	events := scrape(t, buffer)
	require.Len(t, events, 3)
	for i, policy := range []string{"third", "second", "first"} {
		require.Equal(t, policy, events[i].GetPolicy().GetPolicy())
	}
	require.Empty(t, scrape(t, buffer))
	after := bufferStatus(t, buffer)
	require.Zero(t, after.GetBufferedEvents())
	require.Equal(t, uint64(3), after.GetReceivedEvents())
	require.Zero(t, after.GetDroppedEvents())

	require.False(t, buffer.RecordLine(policyLine("next")))
	require.Equal(t, "next", scrape(t, buffer)[0].GetPolicy().GetPolicy())
}

func TestOverflowOverwritesOldest(t *testing.T) {
	buffer := New()
	for i := range MaxBufferEntries {
		require.False(t, buffer.RecordLine(policyLine(strconv.Itoa(i))))
	}
	require.True(t, buffer.RecordLine(policyLine("overflow")))
	before := bufferStatus(t, buffer)
	require.Equal(t, uint64(MaxBufferEntries), before.GetBufferedEvents())
	require.Equal(t, uint64(MaxBufferEntries+1), before.GetReceivedEvents())
	require.Equal(t, uint64(1), before.GetDroppedEvents())

	events := scrape(t, buffer)
	require.Len(t, events, MaxBufferEntries)
	require.Equal(t, "overflow", events[0].GetPolicy().GetPolicy())
	require.Equal(t, "1", events[len(events)-1].GetPolicy().GetPolicy())
	require.Equal(t, uint64(1), bufferStatus(t, buffer).GetDroppedEvents())
	require.False(t, buffer.RecordLine(policyLine("new")))
	require.Equal(t, uint64(1), bufferStatus(t, buffer).GetBufferedEvents())
}

func TestNewBufferDoesNotRecoverEvents(t *testing.T) {
	first := New()
	first.RecordLine(policyLine("lost-on-restart"))
	second := New()
	require.Empty(t, scrape(t, second))
	require.Zero(t, bufferStatus(t, second).GetReceivedEvents())
	require.Len(t, scrape(t, first), 1)
}

func TestCancelledScrapeDoesNotDrain(t *testing.T) {
	buffer := New()
	buffer.RecordLine(policyLine("retained"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	response, err := buffer.ScrapeEvents(ctx, &agentv1.ScrapeEventsRequest{})
	require.Nil(t, response)
	require.Equal(t, codes.Canceled, status.Code(err))
	require.Len(t, scrape(t, buffer), 1)
}

func TestCurrentLogFilesAreCopiedAndDeduplicated(t *testing.T) {
	buffer := New()
	paths := []string{"/logs/b", "/logs/a", "/logs/b"}
	buffer.SetCurrentLogFiles(paths)
	paths[0] = "changed"
	response := bufferStatus(t, buffer)
	require.Equal(t, []string{"/logs/a", "/logs/b"}, response.GetCurrentLogFiles())
	response.CurrentLogFiles[0] = "changed"
	require.Equal(t, []string{"/logs/a", "/logs/b"}, bufferStatus(t, buffer).GetCurrentLogFiles())
	buffer.SetCurrentLogFiles(nil)
	require.Empty(t, bufferStatus(t, buffer).GetCurrentLogFiles())
}

func TestConcurrentRecordScrapeAndStatus(t *testing.T) {
	buffer := New()
	var producers sync.WaitGroup
	for worker := range 4 {
		producers.Go(func() {
			for i := range 100 {
				buffer.RecordLine(policyLine(fmt.Sprintf("%d/%d", worker, i)))
			}
		})
	}
	done := make(chan struct{})
	go func() {
		producers.Wait()
		close(done)
	}()

	var events []*agentv1.Event
	for finished := false; !finished; {
		events = append(events, scrape(t, buffer)...)
		require.LessOrEqual(t, bufferStatus(t, buffer).GetBufferedEvents(), uint64(MaxBufferEntries))
		select {
		case <-done:
			finished = true
		default:
		}
	}
	events = append(events, scrape(t, buffer)...)
	require.Len(t, events, 400)
	seen := make(map[string]bool)
	for _, event := range events {
		key := event.GetPolicy().GetPolicy()
		require.False(t, seen[key], "record delivered more than once: %s", key)
		seen[key] = true
	}
	require.Equal(t, uint64(400), bufferStatus(t, buffer).GetReceivedEvents())
	require.Zero(t, bufferStatus(t, buffer).GetDroppedEvents())
	require.Zero(t, bufferStatus(t, buffer).GetBufferedEvents())
}

func TestParserPreservesOptionalFieldsAndTimestamp(t *testing.T) {
	body := `{"message":"connection complete","direction":"inbound","src.identity":"spiffe://source","dst.identity":"spiffe://destination","dst.workload":"","dst.hbone_addr":"10.0.0.2:08080"}`
	line := []byte("2026-11-02T00:00:00.123Z stdout F " + body)
	buffer := New()
	buffer.RecordLine(line)
	line[len(line)-1] = '!'
	events := scrape(t, buffer)
	require.Len(t, events, 1)
	learn := events[0].GetLearn()
	require.NotNil(t, learn.DestinationName)
	require.Empty(t, learn.GetDestinationName())
	require.Nil(t, learn.DestinationNamespace)
	require.Equal(t, "08080", learn.GetDestinationPort())
	require.NotNil(t, events[0].GetObservedAt())
	require.Equal(t, body, string(events[0].GetRawRecord()))

	event, classified := parseLine([]byte("invalid stdout F " + body))
	require.True(t, classified)
	require.Nil(t, event.GetObservedAt())
	hugePort := strings.Repeat("9", 100)
	event, classified = parseLine(
		[]byte("2026-11-02T00:00:00Z stdout F " + strings.Replace(body, "08080", hugePort, 1)),
	)
	require.True(t, classified)
	require.Equal(t, hugePort, event.GetLearn().GetDestinationPort())
}

func TestParserPolicyModes(t *testing.T) {
	for message, mode := range map[string]agentv1.PolicyMode{
		"deny policy match":                agentv1.PolicyMode_POLICY_MODE_PROTECT,
		"no allow policies matched":        agentv1.PolicyMode_POLICY_MODE_PROTECT,
		"dry-run: deny policy match":       agentv1.PolicyMode_POLICY_MODE_MONITOR,
		"dry-run: no allow policies match": agentv1.PolicyMode_POLICY_MODE_MONITOR,
	} {
		t.Run(message, func(t *testing.T) {
			line := strings.Replace(string(policyLine("ns/deny")), "deny policy match", message, 1)
			event, classified := parseLine([]byte(line))
			require.True(t, classified)
			policy := event.GetPolicy()
			require.Equal(t, mode, policy.GetMode())
			require.Equal(t, message, policy.GetMessage())
			require.Equal(t, "ns/deny", policy.GetPolicy())
			require.Equal(t, "ns/pod", policy.GetDestinationNamespacedName())
			require.Equal(t, "10.0.0.1:1234", policy.GetSourceAddress())
		})
	}
}

func TestParserRejectedRecordsStillCountReceived(t *testing.T) {
	buffer := New()
	lines := []string{
		`2026-11-02T00:00:00Z stdout F {"message":"deny policy match","policy":123}`,
		`2026-11-02T00:00:00Z stdout F {"message":"deny policy match","proxy":false}`,
		`2026-11-02T00:00:00Z stdin F {"message":"deny policy match"}`,
		`{"message":"deny policy match"}`,
		`2026-11-02T00:00:00Z stdout F {invalid json}`,
		`2026-11-02T00:00:00Z stdout F {"message":"ordinary ignored message"}`,
	}
	for _, line := range lines {
		require.False(t, buffer.RecordLine([]byte(line)))
	}
	require.Equal(t, uint64(len(lines)), bufferStatus(t, buffer).GetReceivedEvents())
	require.Zero(t, bufferStatus(t, buffer).GetBufferedEvents())
	require.Zero(t, bufferStatus(t, buffer).GetDroppedEvents())
	require.Empty(t, scrape(t, buffer))
}
