package ztunnel

import (
	"reflect"
	"testing"

	"github.com/kubewarden/network-enforcer/internal/types"
)

const (
	fixtureTimestamp = "2026-10-29T10:45:04.121633Z"
	fixturePrefix    = fixtureTimestamp + " stdout F "
	fixtureSource    = "spiffe://cluster.local/ns/default/sa/http-client-sa"
	fixtureDest      = "spiffe://cluster.local/ns/default/sa/http-server-sa"
	learnFields      = `"message":"connection complete","direction":"inbound","src.identity":"` + fixtureSource +
		`","dst.identity":"` + fixtureDest + `"`
)

type fixture struct {
	name string
	body string
	want map[string]string
}

// These cover the existing Lua test cases as well as missing fields and ports.
func fixtures() []fixture {
	return []fixture{
		{
			name: "monitor_deny_policy",
			body: `{"message":"dry-run: deny policy match","policy":"default/deny-http-server-monitor","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"peer":"10.244.0.9:46266"}}`,
			want: map[string]string{
				"evt.type":            "monitor",
				"dst.namespaced_name": "default/http-server-7bbf596dd9-8gs65",
				"policy":              "default/deny-http-server-monitor",
				"src.addr":            "10.244.0.9:46266",
				"message":             "dry-run: deny policy match",
			},
		},
		{
			name: "monitor_allow_miss",
			body: `{"message":"dry-run: no allow policies match","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"peer":"10.244.0.9:46266"}}`,
			want: map[string]string{
				"evt.type":            "monitor",
				"dst.namespaced_name": "default/http-server-7bbf596dd9-8gs65",
				"policy":              "",
				"src.addr":            "10.244.0.9:46266",
				"message":             "dry-run: no allow policies match",
			},
		},
		{
			name: "protect_deny_policy",
			body: `{"message":"deny policy match","policy":"default/deny-http-server","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"peer":"10.244.0.9:46266"}}`,
			want: map[string]string{
				"evt.type":            "protect",
				"dst.namespaced_name": "default/http-server-7bbf596dd9-8gs65",
				"policy":              "default/deny-http-server",
				"src.addr":            "10.244.0.9:46266",
				"message":             "deny policy match",
			},
		},
		{
			name: "protect_allow_miss",
			body: `{"message":"no allow policies matched","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"peer":"10.244.0.9:46266"}}`,
			want: map[string]string{
				"evt.type":            "protect",
				"dst.namespaced_name": "default/http-server-7bbf596dd9-8gs65",
				"policy":              "",
				"src.addr":            "10.244.0.9:46266",
				"message":             "no allow policies matched",
			},
		},
		{
			name: "policy_missing_fields",
			body: `{"message":"deny policy match"}`,
			want: map[string]string{
				"evt.type":            "protect",
				"dst.namespaced_name": "",
				"policy":              "",
				"src.addr":            "",
				"message":             "deny policy match",
			},
		},
		{
			name: "policy_null_fields",
			body: `{"message":"dry-run: deny policy match","policy":null,"proxy":null,"inbound":null}`,
			want: map[string]string{
				"evt.type":            "monitor",
				"dst.namespaced_name": "",
				"policy":              "",
				"src.addr":            "",
				"message":             "dry-run: deny policy match",
			},
		},
		{name: "monitor_wrong_trigger_message", body: `{"message":"something...dry-run:"}`},
		{
			name: "monitor_allowed_by_policy_match",
			body: `{"message":"dry-run: allow policy match","policy":"default/allow"}`,
		},
		{name: "monitor_allowed_no_policies", body: `{"message":"dry-run: no allow policies, allow"}`},
		{name: "protect_allowed_by_policy_match", body: `{"message":"allow policy match","policy":"default/allow"}`},
		{name: "protect_allowed_no_policies", body: `{"message":"no allow policies, allow"}`},
		{name: "learn_wrong_trigger_message", body: `{"message":"something...connection complete"}`},
		{
			name: "learn_outbound",
			body: `{"message":"connection complete","direction":"outbound","src.identity":"` + fixtureSource + `","dst.identity":"` + fixtureDest + `"}`,
		},
		{
			name: "learn_source_outside_mesh",
			body: `{"message":"connection complete","direction":"inbound","dst.identity":"` + fixtureDest + `"}`,
		},
		{
			name: "learn_destination_outside_mesh",
			body: `{"message":"connection complete","direction":"inbound","src.identity":"` + fixtureSource + `"}`,
		},
		{
			name: "learn_empty_source_identity",
			body: `{"message":"connection complete","direction":"inbound","src.identity":"","dst.identity":"` + fixtureDest + `"}`,
		},
		{
			name: "learn_empty_destination_identity",
			body: `{"message":"connection complete","direction":"inbound","src.identity":"` + fixtureSource + `","dst.identity":""}`,
		},
		{
			name: "learn_inbound",
			body: `{` + learnFields + `,"dst.hbone_addr":"10.244.0.7:18080","dst.workload":"http-server-7bbf596dd9-4rgdc","dst.namespace":"default"}`,
			want: map[string]string{
				"evt.type":      "learn",
				"dst.name":      "http-server-7bbf596dd9-4rgdc",
				"dst.namespace": "default",
				"dst.port":      "18080",
				"src.identity":  fixtureSource,
				"message":       "connection complete",
			},
		},
		{
			name: "learn_missing_destination_fields",
			body: `{` + learnFields + `}`,
			want: map[string]string{
				"evt.type":     "learn",
				"dst.port":     "",
				"src.identity": fixtureSource,
				"message":      "connection complete",
			},
		},
		{
			name: "learn_empty_destination_fields",
			body: `{` + learnFields + `,"dst.workload":"","dst.namespace":"","dst.hbone_addr":""}`,
			want: map[string]string{
				"evt.type":      "learn",
				"dst.name":      "",
				"dst.namespace": "",
				"dst.port":      "",
				"src.identity":  fixtureSource,
				"message":       "connection complete",
			},
		},
		{
			name: "learn_null_destination_fields",
			body: `{` + learnFields + `,"dst.workload":null,"dst.namespace":null,"dst.hbone_addr":null}`,
			want: map[string]string{
				"evt.type":     "learn",
				"dst.port":     "",
				"src.identity": fixtureSource,
				"message":      "connection complete",
			},
		},
		{
			name: "learn_ipv6_port",
			body: `{` + learnFields + `,"dst.hbone_addr":"[::1]:00150"}`,
			want: map[string]string{
				"evt.type":     "learn",
				"dst.port":     "00150",
				"src.identity": fixtureSource,
				"message":      "connection complete",
			},
		},
		{
			name: "learn_invalid_port",
			body: `{` + learnFields + `,"dst.hbone_addr":"10.244.0.7:80abc"}`,
			want: map[string]string{
				"evt.type":     "learn",
				"dst.port":     "",
				"src.identity": fixtureSource,
				"message":      "connection complete",
			},
		},
		{
			name: "learn_empty_port",
			body: `{` + learnFields + `,"dst.hbone_addr":"10.244.0.7:"}`,
			want: map[string]string{
				"evt.type":     "learn",
				"dst.port":     "",
				"src.identity": fixtureSource,
				"message":      "connection complete",
			},
		},
	}
}

func eventAttributes(event Event) map[string]string {
	attrs := map[string]string{"evt.type": string(event.Type), "message": event.Message}
	if event.Type == types.EventTypeLearn {
		if event.DestinationName != nil {
			attrs["dst.name"] = *event.DestinationName
		}
		if event.DestinationNamespace != nil {
			attrs["dst.namespace"] = *event.DestinationNamespace
		}
		attrs["dst.port"] = event.DestinationPort
		attrs["src.identity"] = event.SourceIdentity
	} else {
		attrs["dst.namespaced_name"] = event.DestinationNamespacedName
		attrs["policy"] = event.Policy
		attrs["src.addr"] = event.SourceAddress
	}
	return attrs
}

func TestParse(t *testing.T) {
	for _, tc := range fixtures() {
		t.Run(tc.name, func(t *testing.T) {
			event, matched, err := Parse([]byte(fixturePrefix + tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if matched != (tc.want != nil) {
				t.Fatalf("matched = %v, want %v", matched, tc.want != nil)
			}
			if !matched {
				return
			}
			if event.Timestamp != fixtureTimestamp {
				t.Errorf("timestamp = %q, want %q", event.Timestamp, fixtureTimestamp)
			}
			if got := eventAttributes(event); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("attributes = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestParseCRIAndErrors(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
		matched bool
	}{
		{name: "stderr", line: fixtureTimestamp + ` stderr F {"message":"deny policy match"}`, matched: true},
		{
			name:    "partial_tag_complete_json",
			line:    fixtureTimestamp + ` stdout P {"message":"deny policy match"}`,
			matched: true,
		},
		{name: "empty_tag", line: fixtureTimestamp + ` stdout  {"message":"deny policy match"}`, matched: true},
		{name: "empty_timestamp", line: ` stdout F {"message":"deny policy match"}`, wantErr: true},
		{name: "unknown_stream", line: fixtureTimestamp + ` stdin F {"message":"deny policy match"}`, wantErr: true},
		{name: "missing_tag_separator", line: fixtureTimestamp + " stdout F", wantErr: true},
		{name: "invalid_json", line: fixturePrefix + `{"message":`, wantErr: true},
		{name: "non_object_json", line: fixturePrefix + `[]`, wantErr: true},
		{name: "invalid_proxy", line: fixturePrefix + `{"message":"deny policy match","proxy":true}`, wantErr: true},
		{
			name:    "numeric_source_identity",
			line:    fixturePrefix + `{"message":"connection complete","direction":"inbound","src.identity":123,"dst.identity":"server"}`,
			wantErr: true,
		},
		{
			name:    "numeric_destination_identity",
			line:    fixturePrefix + `{"message":"connection complete","direction":"inbound","src.identity":"client","dst.identity":123}`,
			wantErr: true,
		},
		{
			name:    "boolean_destination_identity",
			line:    fixturePrefix + `{"message":"connection complete","direction":"inbound","src.identity":"client","dst.identity":false}`,
			wantErr: true,
		},
		{name: "non_string_message", line: fixturePrefix + `{"message":123}`, wantErr: true},
		{
			name:    "non_string_policy",
			line:    fixturePrefix + `{"message":"deny policy match","policy":false}`,
			wantErr: true,
		},
		{name: "non_string_workload", line: fixturePrefix + `{` + learnFields + `,"dst.workload":[]}`, wantErr: true},
		{
			name:    "invalid_irrelevant_known_field",
			line:    fixturePrefix + `{"message":"deny policy match","src.identity":123}`,
			wantErr: true,
		},
		{
			name:    "unknown_fields_ignored",
			line:    fixturePrefix + `{"message":"deny policy match","extra":{"value":123}}`,
			matched: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, matched, err := Parse([]byte(tc.line))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if matched != tc.matched {
				t.Errorf("matched = %v, want %v", matched, tc.matched)
			}
		})
	}
}
