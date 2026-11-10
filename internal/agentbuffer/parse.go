package agentbuffer

import (
	"bytes"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/ztunnel"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

func parseLine(line []byte) (*agentv1.Event, bool) {
	parsed, classified, err := ztunnel.Parse(line)
	if err != nil || !classified {
		return nil, false
	}
	body, ok := rawJSONBody(line)
	if !ok {
		return nil, false
	}
	event := &agentv1.Event{
		ObservedAt: parseObservedAt(parsed.Timestamp),
		RawRecord:  append([]byte(nil), body...),
	}
	switch parsed.Type {
	case types.EventTypeLearn:
		event.Kind = &agentv1.Event_Learn{Learn: toLearnEvent(parsed)}
	case types.EventTypeMonitor, types.EventTypeProtect:
		event.Kind = &agentv1.Event_Policy{Policy: toPolicyEvent(parsed)}
	default:
		return nil, false
	}
	return event, true
}

func toLearnEvent(parsed ztunnel.Event) *agentv1.LearnEvent {
	learn := &agentv1.LearnEvent{
		SourceIdentity:  parsed.SourceIdentity,
		DestinationPort: parsed.DestinationPort,
	}
	if parsed.DestinationName != nil {
		value := *parsed.DestinationName
		learn.DestinationName = &value
	}
	if parsed.DestinationNamespace != nil {
		value := *parsed.DestinationNamespace
		learn.DestinationNamespace = &value
	}
	return learn
}

func toPolicyEvent(parsed ztunnel.Event) *agentv1.PolicyEvent {
	mode := agentv1.PolicyMode_POLICY_MODE_PROTECT
	if parsed.Type == types.EventTypeMonitor {
		mode = agentv1.PolicyMode_POLICY_MODE_MONITOR
	}
	return &agentv1.PolicyEvent{
		Mode: mode, Message: parsed.Message,
		DestinationNamespacedName: parsed.DestinationNamespacedName,
		Policy:                    parsed.Policy, SourceAddress: parsed.SourceAddress,
	}
}

// rawJSONBody strips a CRI prefix only after Parse accepted the complete line.
func rawJSONBody(line []byte) ([]byte, bool) {
	first := bytes.IndexByte(line, ' ')
	if first < 0 {
		return nil, false
	}
	secondRelative := bytes.IndexByte(line[first+1:], ' ')
	if secondRelative < 0 {
		return nil, false
	}
	second := first + 1 + secondRelative
	thirdRelative := bytes.IndexByte(line[second+1:], ' ')
	if thirdRelative < 0 {
		return nil, false
	}
	third := second + 1 + thirdRelative
	return line[third+1:], true
}

func parseObservedAt(timestamp string) *timestamppb.Timestamp {
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return nil
	}
	ts := timestamppb.New(parsed)
	if ts.CheckValid() != nil {
		return nil
	}
	return ts
}
