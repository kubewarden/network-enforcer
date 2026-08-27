package scraper

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

const (
	scriptPath      = "../../charts/network-enforcer/files/istio-fluent-bit/ztunnel_to_otel.lua"
	learningMessage = "connection complete"
)

func TestLuaScript(t *testing.T) {
	tests := []struct {
		name              string
		record            map[string]any
		expectedOtelEvent map[string]string
	}{
		{
			// Example with a DENY policy (so the name of the policy is present)
			// {"level":"info","time":"2026-08-11T10:45:04.121633Z","scope":"ztunnel::state","message":"dry-run: deny policy match","policy":"default/deny-http-server-monitor","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"id":"4703222e84d01205aa1511f86681682f","peer":"10.244.0.9:46266"}}
			name: "monitor_deny_policy",
			record: map[string]any{
				"message": "dry-run: deny policy match",
				"policy":  "default/deny-http-server-monitor",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
				"inbound": map[string]any{
					"id":   "4703222e84d01205aa1511f86681682f",
					"peer": "10.244.0.9:46266",
				},
			},
			expectedOtelEvent: map[string]string{
				eventTypeKey:         eventTypeMonitor,
				dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
				policyKey:            "default/deny-http-server-monitor",
				srcAddrKey:           "10.244.0.9:46266",
				messageKey:           "dry-run: deny policy match",
			},
		},
		{
			// Example with a ALLOW policy (so the name of the policy is not present)
			// {"level":"info","time":"2026-08-11T10:46:53.334606Z","scope":"ztunnel::state","message":"dry-run: no allow policies match","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"id":"8772382321babc31fe9da8ce6cb9ca31","peer":"10.244.0.9:46266"}}
			name: "monitor_allow_policy",
			record: map[string]any{
				"message": "dry-run: no allow policies match",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
				"inbound": map[string]any{
					"id":   "8772382321babc31fe9da8ce6cb9ca31",
					"peer": "10.244.0.9:46266",
				},
			},
			expectedOtelEvent: map[string]string{
				eventTypeKey:         eventTypeMonitor,
				dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
				policyKey:            "",
				srcAddrKey:           "10.244.0.9:46266",
				messageKey:           "dry-run: no allow policies match",
			},
		},
		{
			name: "monitor_wrong_trigger_message",
			record: map[string]any{
				// the message doesn't start with dry-run so we don't consider this log.
				"message": "something...dry-run:",
			},
			expectedOtelEvent: nil,
		},
		{
			// Monitor dry-run allowed flow via an explicit ALLOW match: the
			// message is `dry-run:`-prefixed but it is not a rejection, so it
			// must be dropped (mirrors the protect-mode allowed case).
			name: "monitor_allowed_by_policy_match",
			record: map[string]any{
				"message": "dry-run: allow policy match",
				"policy":  "default/allow-http-server-monitor",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
			},
			expectedOtelEvent: nil,
		},
		{
			// Monitor dry-run allowed flow when no allow policies exist at all:
			// permitted, so it must be dropped and not confused with the
			// ALLOW-miss rejection ("dry-run: no allow policies match").
			name: "monitor_allowed_no_policies",
			record: map[string]any{
				"message": "dry-run: no allow policies, allow",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
			},
			expectedOtelEvent: nil,
		},
		{
			// Protect enforcement: an explicit DENY match carries the policy name.
			// {"level":"info","scope":"ztunnel::state","message":"deny policy match","policy":"default/deny-http-server","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"id":"...","peer":"10.244.0.9:46266"}}
			name: "violation_deny_policy",
			record: map[string]any{
				"message": "deny policy match",
				"policy":  "default/deny-http-server",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
				"inbound": map[string]any{
					"id":   "4703222e84d01205aa1511f86681682f",
					"peer": "10.244.0.9:46266",
				},
			},
			expectedOtelEvent: map[string]string{
				eventTypeKey:         eventTypeProtect,
				dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
				policyKey:            "default/deny-http-server",
				srcAddrKey:           "10.244.0.9:46266",
				messageKey:           "deny policy match",
			},
		},
		{
			// Protect enforcement: an ALLOW-miss rejection has no denying policy,
			// so the policy name is left empty.
			// {"level":"info","scope":"ztunnel::state","message":"no allow policies matched","proxy":{"wl":"default/http-server-7bbf596dd9-8gs65"},"inbound":{"id":"...","peer":"10.244.0.9:46266"}}
			name: "violation_allow_miss",
			record: map[string]any{
				"message": "no allow policies matched",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
				"inbound": map[string]any{
					"id":   "8772382321babc31fe9da8ce6cb9ca31",
					"peer": "10.244.0.9:46266",
				},
			},
			expectedOtelEvent: map[string]string{
				eventTypeKey:         eventTypeProtect,
				dstNamespacedNameKey: "default/http-server-7bbf596dd9-8gs65",
				policyKey:            "",
				srcAddrKey:           "10.244.0.9:46266",
				messageKey:           "no allow policies matched",
			},
		},
		{
			// Protect enforcement allowed flow via an explicit ALLOW match: this
			// is not a violation and must be dropped.
			name: "violation_allowed_by_policy_match",
			record: map[string]any{
				"message": "allow policy match",
				"policy":  "default/allow-http-server",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
			},
			expectedOtelEvent: nil,
		},
		{
			// Protect enforcement allowed flow when no allow policies exist at all
			// ("no allow policies, allow"): permitted, so it must be dropped and
			// not confused with the ALLOW-miss rejection ("no allow policies matched").
			name: "violation_allowed_no_policies",
			record: map[string]any{
				"message": "no allow policies, allow",
				"proxy": map[string]any{
					"wl": "default/http-server-7bbf596dd9-8gs65",
				},
			},
			expectedOtelEvent: nil,
		},
		{
			// {"level":"info","time":"2026-08-10T08:19:58.950669Z","scope":"access","message":"connection complete","src.addr":"10.244.0.6:57866","src.workload":"http-client-7fc85576c4-h95l5","src.namespace":"default","src.identity":"spiffe://cluster.local/ns/default/sa/http-client-sa","dst.addr":"10.244.0.7:15008","dst.hbone_addr":"10.244.0.7:18080","dst.service":"http-service.default.svc.cluster.local","dst.workload":"http-server-7bbf596dd9-4rgdc","dst.namespace":"default","dst.identity":"spiffe://cluster.local/ns/default/sa/http-server-sa","direction":"outbound","bytes_sent":16,"bytes_recv":16,"duration":"1006ms"}
			name: "learn_outbound",
			record: map[string]any{
				"message":        learningMessage,
				"src.identity":   "spiffe://cluster.local/ns/default/sa/http-client-sa",
				"dst.hbone_addr": "10.244.0.7:18080",
				"dst.workload":   "http-server-7bbf596dd9-4rgdc",
				"dst.namespace":  "default",
				"direction":      "outbound",
			},
			// we ignore outbound events
			expectedOtelEvent: nil,
		},
		{
			// {"level":"info","time":"2026-08-10T08:19:58.949999Z","scope":"access","message":"connection complete","src.addr":"10.244.0.6:59470","src.workload":"http-client-7fc85576c4-h95l5","src.namespace":"default","src.identity":"spiffe://cluster.local/ns/default/sa/http-client-sa","dst.addr":"10.244.0.7:15008","dst.hbone_addr":"10.244.0.7:18080","dst.service":"http-service.default.svc.cluster.local","dst.workload":"http-server-7bbf596dd9-4rgdc","dst.namespace":"default","dst.identity":"spiffe://cluster.local/ns/default/sa/http-server-sa","direction":"inbound","bytes_sent":16,"bytes_recv":16,"duration":"1004ms"}
			name: "learn_inbound",
			record: map[string]any{
				"message":        learningMessage,
				"src.identity":   "spiffe://cluster.local/ns/default/sa/http-client-sa",
				"dst.identity":   "spiffe://cluster.local/ns/default/sa/http-server-sa",
				"dst.hbone_addr": "10.244.0.7:18080",
				"dst.workload":   "http-server-7bbf596dd9-4rgdc",
				"dst.namespace":  "default",
				"direction":      "inbound",
			},
			expectedOtelEvent: map[string]string{
				eventTypeKey:    eventTypeLearn,
				dstNameKey:      "http-server-7bbf596dd9-4rgdc",
				dstNamespaceKey: "default",
				dstPortKey:      "18080",
				srcIdentityKey:  "spiffe://cluster.local/ns/default/sa/http-client-sa",
				messageKey:      learningMessage,
			},
		},
		{
			// src.addr=10.244.0.17:34010 src.workload="client" src.namespace="istio-system" dst.addr=10.244.1.15:18080 dst.service="http-service.default.svc.cluster.local" dst.workload="http-server-6cbcc86f5d-bxb9w" dst.namespace="default" direction="inbound" bytes_sent=16 bytes_recv=16 duration="1004ms"
			name: "learn_source_outside_mesh",
			record: map[string]any{
				"message":       learningMessage,
				"dst.workload":  "http-server-6cbcc86f5d-bxb9w",
				"dst.namespace": "default",
				"dst.addr":      "10.244.1.15:18080",
				"direction":     "inbound",
			},
			expectedOtelEvent: nil,
		},
		{
			// complete src.addr=10.244.0.5:54646 src.workload="http-client-6b4b85489f-t6sl2" src.namespace="default" dst.addr=142.251.209.46:80 direction="outbound" bytes_sent=74 bytes_recv=773 duration="357ms"
			// in case of destination outside the mesh the direction will be always outbound so the traffic is dropped for 2 reasons:
			// 1. the destination identity is not present
			// 2. the direction is outbound
			name: "learn_destination_outside_mesh",
			record: map[string]any{
				"message":       learningMessage,
				"src.workload":  "http-client-6b4b85489f-t6sl2",
				"src.namespace": "default",
				"dst.addr":      "142.251.209.46:80",
				"direction":     "outbound",
			},
			expectedOtelEvent: nil,
		},
		{
			name: "learn_wrong_trigger_message",
			record: map[string]any{
				// this is not a trigger for the learning event
				"message": fmt.Sprintf("something...%s", learningMessage),
			},
			expectedOtelEvent: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out := executeToOtelFn(t, tc.record)
			if tc.expectedOtelEvent == nil {
				require.Equal(t, -1, code)
				return
			}
			require.Equal(t, 1, code)
			require.Equal(t, tc.expectedOtelEvent, luaMapToGo(out))
		})
	}
}

func executeToOtelFn(t *testing.T, record map[string]any) (int, *lua.LTable) {
	t.Helper()

	luaState := lua.NewState()
	defer luaState.Close()

	contentBytes, err := os.ReadFile(scriptPath)
	require.NoError(t, err)

	scriptContent := string(contentBytes)
	require.NoError(t, luaState.DoString(scriptContent))

	fn := luaState.GetGlobal("to_otel")
	require.Equal(t, lua.LTFunction, fn.Type())

	// We prepare the Lua stack for the function call
	luaState.Push(fn)
	// first argument: tag (not relevant here)
	luaState.Push(lua.LString("mytag"))
	// second argument: timestamp (not relevant here)
	luaState.Push(lua.LNumber(0))
	// third argument: record
	luaState.Push(goValueToLua(luaState, record))
	require.NoError(t, luaState.PCall(3, 3, nil))

	// the last return value is the output table.
	// we are reading return values in reverse order.
	outVal := luaState.Get(-1)
	table, ok := outVal.(*lua.LTable)
	require.True(t, ok)

	// the second return is the timestamp so we ignore it.

	// the first return is the status code.
	codeVal := luaState.Get(-3)
	code, ok := codeVal.(lua.LNumber)
	require.True(t, ok)
	luaState.Pop(3)
	return int(code), table
}

func goValueToLua(luaState *lua.LState, v any) lua.LValue {
	switch value := v.(type) {
	case nil:
		return lua.LNil
	case string:
		return lua.LString(value)
	case bool:
		return lua.LBool(value)
	case int:
		return lua.LNumber(value)
	case int32:
		return lua.LNumber(value)
	case int64:
		return lua.LNumber(value)
	case float64:
		return lua.LNumber(value)
	case map[string]any:
		tbl := luaState.NewTable()
		for k, item := range value {
			tbl.RawSetString(k, goValueToLua(luaState, item))
		}
		return tbl
	case []any:
		tbl := luaState.NewTable()
		for i, item := range value {
			tbl.RawSetInt(i+1, goValueToLua(luaState, item))
		}
		return tbl
	default:
		return lua.LNil
	}
}

func luaMapToGo(tbl *lua.LTable) map[string]string {
	result := make(map[string]string)
	tbl.ForEach(func(key, value lua.LValue) {
		result[key.String()] = value.String()
	})
	return result
}
