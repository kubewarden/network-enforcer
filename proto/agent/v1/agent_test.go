package agentv1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_ AgentServiceClient = (*agentServiceClient)(nil)
	_ AgentServiceServer = (*UnimplementedAgentServiceServer)(nil)
)

func TestAgentServiceDescriptor(t *testing.T) {
	service := File_proto_agent_v1_agent_proto.Services().ByName("AgentService")
	require.NotNil(t, service, "AgentService descriptor is missing")
	require.Equal(t, 2, service.Methods().Len())

	methods := map[protoreflect.Name][2]protoreflect.Name{
		"PullEvents": {"PullEventsRequest", "PullEventsResponse"},
		"GetStatus":  {"GetStatusRequest", "GetStatusResponse"},
	}
	for name, types := range methods {
		method := service.Methods().ByName(name)
		require.NotNil(t, method, "AgentService method %q is missing", name)
		assert.False(t, method.IsStreamingClient(), "AgentService.%s must be unary", name)
		assert.False(t, method.IsStreamingServer(), "AgentService.%s must be unary", name)
		assert.Equal(t, types[0], method.Input().Name(), "AgentService.%s input", name)
		assert.Equal(t, types[1], method.Output().Name(), "AgentService.%s output", name)
	}
	assert.Equal(t, "agent.v1.AgentService", AgentService_ServiceDesc.ServiceName)
	assert.Empty(t, AgentService_ServiceDesc.Streams)
}

func TestPullAndStatusFieldDescriptors(t *testing.T) {
	file := File_proto_agent_v1_agent_proto
	request := file.Messages().ByName("PullEventsRequest")
	assertField(t, request, "epoch", 1, protoreflect.StringKind)
	assertField(t, request, "since_seq", 2, protoreflect.Uint64Kind)
	assertField(t, request, "limit", 3, protoreflect.Uint32Kind)

	response := file.Messages().ByName("PullEventsResponse")
	assertField(t, response, "acked_seq", 2, protoreflect.Uint64Kind)
	assertField(t, response, "newest_seq", 3, protoreflect.Uint64Kind)
	events := assertField(t, response, "events", 4, protoreflect.MessageKind)
	assert.Equal(t, protoreflect.Repeated, events.Cardinality())
	assertField(t, response, "gap", 5, protoreflect.BoolKind)
	assertField(t, response, "dropped", 6, protoreflect.Uint64Kind)

	status := file.Messages().ByName("GetStatusResponse")
	assertField(t, status, "oldest_seq", 4, protoreflect.Uint64Kind)
	assertField(t, status, "newest_seq", 3, protoreflect.Uint64Kind)
	assertField(t, status, "buffered_events", 5, protoreflect.Uint64Kind)
	assertField(t, status, "max_events", 6, protoreflect.Uint64Kind)
	assertField(t, status, "dropped_events", 8, protoreflect.Uint64Kind)
	logFiles := assertField(t, status, "current_log_files", 9, protoreflect.StringKind)
	assert.Equal(t, protoreflect.Repeated, logFiles.Cardinality())
	received := assertField(t, status, "received_events", 10, protoreflect.Uint64Kind)
	assert.Equal(t, protoreflect.Optional, received.Cardinality())
	maxAge := assertField(t, status, "max_age", 7, protoreflect.MessageKind)
	assert.Equal(t, protoreflect.FullName("google.protobuf.Duration"), maxAge.Message().FullName())
}

func TestEventFieldAndOneofDescriptors(t *testing.T) {
	file := File_proto_agent_v1_agent_proto
	event := file.Messages().ByName("Event")
	require.NotNil(t, event, "Event descriptor is missing")
	observedAt := assertField(t, event, "observed_at", 2, protoreflect.MessageKind)
	assert.Equal(t, protoreflect.FullName("google.protobuf.Timestamp"), observedAt.Message().FullName())
	assert.True(t, observedAt.HasPresence())
	assertField(t, event, "seq", 1, protoreflect.Uint64Kind)
	assertField(t, event, "raw_record", 5, protoreflect.BytesKind)

	kind := event.Oneofs().ByName("kind")
	require.NotNil(t, kind, "Event.kind oneof is missing")
	require.Equal(t, 2, kind.Fields().Len())
	for _, name := range []protoreflect.Name{"learn", "policy"} {
		field := event.Fields().ByName(name)
		require.NotNil(t, field, "Event.%s is missing", name)
		assert.Equal(t, kind, field.ContainingOneof(), "Event.%s oneof", name)
	}

	learn := file.Messages().ByName("LearnEvent")
	require.NotNil(t, learn, "LearnEvent descriptor is missing")
	for _, name := range []protoreflect.Name{"destination_name", "destination_namespace"} {
		field := learn.Fields().ByName(name)
		require.NotNil(t, field, "LearnEvent.%s is missing", name)
		assert.True(t, field.HasPresence(), "LearnEvent.%s must have presence", name)
		assert.True(t, field.HasOptionalKeyword(), "LearnEvent.%s must be optional", name)
	}
	assertField(t, learn, "destination_port", 4, protoreflect.StringKind)
}

func TestPolicyModeDescriptor(t *testing.T) {
	policy := File_proto_agent_v1_agent_proto.Messages().ByName("PolicyEvent")
	require.NotNil(t, policy, "PolicyEvent descriptor is missing")
	mode := policy.Fields().ByName("mode")
	require.NotNil(t, mode, "PolicyEvent.mode is missing")
	require.NotNil(t, mode.Enum(), "PolicyEvent.mode enum is missing")
	for name, want := range map[protoreflect.Name]protoreflect.EnumNumber{
		"POLICY_MODE_UNSPECIFIED": 0,
		"POLICY_MODE_MONITOR":     1,
		"POLICY_MODE_PROTECT":     2,
	} {
		value := mode.Enum().Values().ByName(name)
		require.NotNil(t, value, "policy mode %q is missing", name)
		assert.Equal(t, want, value.Number(), "%s", name)
	}
}

func assertField(
	t *testing.T,
	message protoreflect.MessageDescriptor,
	name protoreflect.Name,
	number protoreflect.FieldNumber,
	kind protoreflect.Kind,
) protoreflect.FieldDescriptor {
	t.Helper()
	require.NotNil(t, message, "message descriptor is missing while checking field %q", name)
	field := message.Fields().ByName(name)
	require.NotNil(t, field, "%s.%s descriptor is missing", message.Name(), name)
	assert.Equal(t, number, field.Number(), "%s.%s number", message.Name(), name)
	require.Equal(t, kind, field.Kind(), "%s.%s kind", message.Name(), name)
	return field
}

func TestLearnEventBinaryRoundTrip(t *testing.T) {
	observedAt := time.Date(2026, time.November, 2, 12, 34, 56, 789000000, time.UTC)
	emptyName := ""
	original := &Event{
		Seq:        17,
		ObservedAt: timestamppb.New(observedAt),
		Kind: &Event_Learn{Learn: &LearnEvent{
			SourceIdentity:       "spiffe://cluster.local/ns/source/sa/client",
			DestinationName:      &emptyName,
			DestinationNamespace: nil,
			DestinationPort:      "65536",
		}},
		RawRecord: []byte{0x7b, 0x00, 0xff, 0x7d},
	}

	got := marshalRoundTrip(t, original).(*Event)
	require.True(
		t,
		proto.Equal(original, got),
		"learn event changed after binary round trip:\n got: %v\nwant: %v",
		got,
		original,
	)
	assert.NotNil(t, got.GetLearn().DestinationName, "present-but-empty destination_name lost presence")
	assert.Empty(t, got.GetLearn().GetDestinationName())
	assert.Nil(t, got.GetLearn().DestinationNamespace, "absent destination_namespace gained presence")
	assert.Equal(t, original.GetRawRecord(), got.GetRawRecord())
}

func TestPolicyEventBinaryRoundTripWithoutTimestamp(t *testing.T) {
	original := &Event{
		Seq: 9,
		Kind: &Event_Policy{Policy: &PolicyEvent{
			Mode:                      PolicyMode_POLICY_MODE_PROTECT,
			Message:                   "deny policy match",
			DestinationNamespacedName: "payments/api",
			Policy:                    "payments/deny-external",
			SourceAddress:             "10.0.0.7:50123",
		}},
		RawRecord: []byte(`{"message":"deny policy match"}`),
	}

	got := marshalRoundTrip(t, original).(*Event)
	require.True(
		t,
		proto.Equal(original, got),
		"policy event changed after binary round trip:\n got: %v\nwant: %v",
		got,
		original,
	)
	assert.Nil(t, got.GetObservedAt())
	assert.Equal(t, PolicyMode_POLICY_MODE_PROTECT, got.GetPolicy().GetMode())
}

func TestStatusBinaryRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		status *GetStatusResponse
	}{
		{
			name:   "no input or monitored files",
			status: &GetStatusResponse{Epoch: "empty", MaxEvents: 10_000},
		},
		{
			name: "multiple monitored files with retained events",
			status: &GetStatusResponse{
				Epoch:          "active",
				AckedSeq:       12,
				NewestSeq:      17,
				OldestSeq:      15,
				BufferedEvents: 3,
				MaxEvents:      10_000,
				MaxAge:         durationpb.New(5 * time.Minute),
				DroppedEvents:  2,
				CurrentLogFiles: []string{
					"/var/log/containers/ztunnel-a_istio-system_ztunnel-first.log",
					"/var/log/containers/ztunnel-b_istio-system_ztunnel-second.log",
				},
				ReceivedEvents: 42,
			},
		},
		{
			name: "input received without producing events",
			status: &GetStatusResponse{
				Epoch:           "filtered",
				MaxEvents:       10_000,
				CurrentLogFiles: []string{"/var/log/containers/ztunnel.log"},
				ReceivedEvents:  42,
			},
		},
		{
			name: "received total retained after acknowledged events are purged",
			status: &GetStatusResponse{
				Epoch:          "drained",
				AckedSeq:       17,
				NewestSeq:      17,
				MaxEvents:      10_000,
				ReceivedEvents: 42,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := marshalRoundTrip(t, tc.status).(*GetStatusResponse)
			require.True(t, proto.Equal(tc.status, got),
				"status changed after binary round trip:\n got: %v\nwant: %v", got, tc.status)
			assert.Equal(t, tc.status.GetCurrentLogFiles(), got.GetCurrentLogFiles())
			assert.Equal(t, tc.status.GetReceivedEvents(), got.GetReceivedEvents())
		})
	}
}

func marshalRoundTrip(t *testing.T, message proto.Message) proto.Message {
	t.Helper()
	encoded, err := proto.Marshal(message)
	require.NoError(t, err, "marshal protobuf")
	decoded := message.ProtoReflect().Type().New().Interface()
	require.NoError(t, proto.Unmarshal(encoded, decoded), "unmarshal protobuf")
	return decoded
}
