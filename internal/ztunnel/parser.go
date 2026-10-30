// Package ztunnel parses CRI-wrapped ztunnel logs into Istio events.
// It is independent of the existing Fluent Bit pipeline.
package ztunnel

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/kubewarden/network-enforcer/internal/types"
)

// Event contains the attributes of a ztunnel learn, monitor, or protect event.
// DestinationName and DestinationNamespace are nil when absent or null,
// and point to empty strings when the fields are present but empty.
// Timestamp is the unmodified CRI timestamp, not the timestamp in the JSON body.
type Event struct {
	Type                      types.EventType
	Timestamp                 string
	Message                   string
	DestinationName           *string
	DestinationNamespace      *string
	DestinationPort           string
	SourceIdentity            string
	DestinationNamespacedName string
	Policy                    string
	SourceAddress             string
}

type record struct {
	Message              string        `json:"message"`
	Direction            string        `json:"direction"`
	SourceIdentity       string        `json:"src.identity"`
	DestinationIdentity  string        `json:"dst.identity"`
	DestinationName      *string       `json:"dst.workload"`
	DestinationNamespace *string       `json:"dst.namespace"`
	DestinationHBONEAddr string        `json:"dst.hbone_addr"`
	Policy               string        `json:"policy"`
	Proxy                proxyRecord   `json:"proxy"`
	Inbound              inboundRecord `json:"inbound"`
}

type proxyRecord struct {
	Workload string `json:"wl"`
}

type inboundRecord struct {
	Peer string `json:"peer"`
}

var errInvalidCRI = errors.New("invalid CRI log prefix")

// Parse parses one CRI log line. The boolean is false for a valid record that
// does not produce an event. Malformed CRI, JSON, or field types return an
// error. It accepts full and partial CRI tags but does not join fragments.
// Known attributes must be strings or null, and proxy/inbound must be objects
// or null. Unknown fields are ignored. Field names are case-sensitive.
func Parse(line []byte) (Event, bool, error) {
	first := bytes.IndexByte(line, ' ')
	if first <= 0 {
		return Event{}, false, errInvalidCRI
	}
	timestamp := line[:first]
	line = line[first+1:]

	second := bytes.IndexByte(line, ' ')
	if second < 0 || (!bytes.Equal(line[:second], []byte("stdout")) && !bytes.Equal(line[:second], []byte("stderr"))) {
		return Event{}, false, errInvalidCRI
	}
	line = line[second+1:]
	third := bytes.IndexByte(line, ' ')
	if third < 0 {
		return Event{}, false, errInvalidCRI
	}
	line = line[third+1:]

	var rec record
	if err := json.Unmarshal(line, &rec); err != nil {
		return Event{}, false, fmt.Errorf("decode ztunnel JSON: %w", err)
	}

	event := Event{Timestamp: string(timestamp), Message: rec.Message}
	switch rec.Message {
	case "dry-run: deny policy match", "dry-run: no allow policies match":
		event.Type = types.EventTypeMonitor
	case "deny policy match", "no allow policies matched":
		event.Type = types.EventTypeProtect
	case "connection complete":
		if rec.Direction != "inbound" || rec.SourceIdentity == "" || rec.DestinationIdentity == "" {
			return Event{}, false, nil
		}
		event.Type = types.EventTypeLearn
		event.DestinationName = rec.DestinationName
		event.DestinationNamespace = rec.DestinationNamespace
		event.DestinationPort = extractPort(rec.DestinationHBONEAddr)
		event.SourceIdentity = rec.SourceIdentity
		return event, true, nil
	default:
		return Event{}, false, nil
	}

	event.DestinationNamespacedName = rec.Proxy.Workload
	event.Policy = rec.Policy
	event.SourceAddress = rec.Inbound.Peer
	return event, true, nil
}

func extractPort(address string) string {
	colon := strings.LastIndexByte(address, ':')
	if colon < 0 || colon == len(address)-1 {
		return ""
	}
	for _, digit := range address[colon+1:] {
		if digit < '0' || digit > '9' {
			return ""
		}
	}
	return address[colon+1:]
}
