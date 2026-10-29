package ztunnel

import (
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/goccy/go-json"
	lua "github.com/yuin/gopher-lua"
)

// TODO: Remove this parity test when the chart cuts over from the Lua filter.
// Parity covers the supported ztunnel schema, not Lua's non-string coercions.
func TestLuaParity(t *testing.T) {
	script, err := os.ReadFile("../../charts/network-enforcer/files/istio-fluent-bit/ztunnel_to_otel.lua")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range slices.Concat(fixtures(), parityEdgeFixtures()) {
		t.Run(tc.name, func(t *testing.T) {
			want := executeLuaEvent(t, string(script), tc.body)
			event, matched, parseErr := Parse([]byte(fixturePrefix + tc.body))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if matched != (want != nil) {
				t.Fatalf("Go matched = %v, Lua matched = %v", matched, want != nil)
			}
			if !matched {
				return
			}
			if got := eventAttributes(event); !reflect.DeepEqual(got, want) {
				t.Errorf("Go event = %#v, Lua event = %#v", got, want)
			}
		})
	}
}

func executeLuaEvent(t *testing.T, script, body string) map[string]string {
	t.Helper()
	var input map[string]any
	if err := json.Unmarshal([]byte(body), &input); err != nil {
		t.Fatal(err)
	}

	state := lua.NewState()
	defer state.Close()
	if err := state.DoString(script); err != nil {
		t.Fatal(err)
	}
	fn := state.GetGlobal("to_otel")
	if fn.Type() != lua.LTFunction {
		t.Fatalf("to_otel is %s, not a function", fn.Type())
	}
	state.Push(fn)
	state.Push(lua.LString("istio.ztunnel"))
	state.Push(lua.LNumber(0))
	state.Push(toLua(state, input))
	if err := state.PCall(3, 3, nil); err != nil {
		t.Fatal(err)
	}
	code, ok := state.Get(-3).(lua.LNumber)
	if !ok {
		t.Fatalf("Lua return code is %s", state.Get(-3).Type())
	}
	switch code {
	case -1:
		return nil
	case 1:
		return luaEventAttributes(t, state.Get(-1))
	default:
		t.Fatalf("unexpected Lua return code %v", code)
		return nil
	}
}

func luaEventAttributes(t *testing.T, value lua.LValue) map[string]string {
	t.Helper()
	table, ok := value.(*lua.LTable)
	if !ok {
		t.Fatalf("Lua event is %s, not a table", value.Type())
	}
	attrs := make(map[string]string)
	table.ForEach(func(key, value lua.LValue) {
		k, keyOK := key.(lua.LString)
		v, valueOK := value.(lua.LString)
		if !keyOK || !valueOK {
			t.Fatalf("Lua event contains non-string attribute: %v = %v", key, value)
		}
		attrs[string(k)] = string(v)
	})
	return attrs
}

func parityEdgeFixtures() []fixture {
	return []fixture{
		{name: "uppercase_message", body: `{"MESSAGE":"deny policy match"}`},
		{name: "mixed_case_message", body: `{"Message":"deny policy match"}`},
		{
			name: "uppercase_direction",
			body: `{"message":"connection complete","DIRECTION":"inbound","src.identity":"client","dst.identity":"server"}`,
		},
		{
			name: "uppercase_identity",
			body: `{"message":"connection complete","direction":"inbound","SRC.IDENTITY":"client","dst.identity":"server"}`,
		},
		{
			name: "uppercase_policy_keys",
			body: `{"message":"deny policy match","POLICY":"default/deny","PROXY":{"wl":"default/server"},"INBOUND":{"peer":"1.2.3.4:80"}}`,
		},
		{
			name: "uppercase_nested_keys",
			body: `{"message":"deny policy match","proxy":{"WL":"default/server"},"inbound":{"PEER":"1.2.3.4:80"}}`,
		},
		{name: "case_variant_does_not_override", body: `{"message":"deny policy match","MESSAGE":"unrelated"}`},
		{
			name: "escaped_field_names",
			body: `{"mess\u0061ge":"deny policy match","proxy":{"w\u006c":"default/server"}}`,
		},
	}
}

func toLua(state *lua.LState, value any) lua.LValue {
	switch v := value.(type) {
	case nil:
		return lua.LNil
	case string:
		return lua.LString(v)
	case bool:
		return lua.LBool(v)
	case float64:
		return lua.LNumber(v)
	case map[string]any:
		table := state.NewTable()
		for key, item := range v {
			table.RawSetString(key, toLua(state, item))
		}
		return table
	case []any:
		table := state.NewTable()
		for i, item := range v {
			table.RawSetInt(i+1, toLua(state, item))
		}
		return table
	default:
		panic("unexpected JSON value")
	}
}
