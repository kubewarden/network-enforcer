package violation

import (
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

const collectorConfigMapPath = "../../charts/network-enforcer/templates/otel-collector/configmap.yaml"

var (
	// countConnectorKeyRE matches the `- key: <attribute>` entries of the count
	// connector attribute list.
	countConnectorKeyRE = regexp.MustCompile(`(?m)^\s*- key:\s*(\S+)\s*$`)
	// ottlAttributeRE matches attribute lookups in the OTTL conditions, e.g.
	// 'attributes["enforcement.provider"] != nil'.
	ottlAttributeRE = regexp.MustCompile(`attributes\["([^"]+)"\]`)
)

func TestChartCountConnectorMatchesOtelSchema(t *testing.T) {
	raw, err := os.ReadFile(collectorConfigMapPath)
	require.NoError(t, err, "collector ConfigMap must be readable from the emitter package")

	schema := map[string]bool{}
	for _, key := range OtelAttributeKeys() {
		schema[key] = true
	}

	countedKeys := map[string]bool{}
	for _, match := range countConnectorKeyRE.FindAllStringSubmatch(string(raw), -1) {
		key := match[1]
		require.True(t, schema[key],
			"count connector counts by %q, which the emitter never writes", key)
		countedKeys[key] = true
	}
	require.NotEmpty(t, countedKeys, "count connector attribute list must not be empty")

	for _, match := range ottlAttributeRE.FindAllStringSubmatch(string(raw), -1) {
		require.True(t, schema[match[1]],
			"collector condition filters on %q, which the emitter never writes", match[1])
	}

	// The provider is the only attribute always present, so it carries both the
	// condition and the metric dimension the pipeline relies on.
	require.True(t, countedKeys[otelAttrEnforcementProvider],
		"count connector must count by %q", otelAttrEnforcementProvider)
	require.True(t, countedKeys[otelAttrAction],
		"count connector must count by %q to separate monitor from protect", otelAttrAction)
}

func TestEmittedAttributesAreCounted(t *testing.T) {
	keys := OtelAttributeKeys()
	require.Len(t, slices.Compact(slices.Sorted(slices.Values(keys))), len(keys),
		"attribute schema must not repeat a key")

	raw, err := os.ReadFile(collectorConfigMapPath)
	require.NoError(t, err)

	counted := map[string]bool{}
	for _, match := range countConnectorKeyRE.FindAllStringSubmatch(string(raw), -1) {
		counted[match[1]] = true
	}

	// Kind and identity are high-cardinality and intentionally not metric
	// dimensions: they stay on the log record only.
	logOnly := map[string]bool{
		otelAttrSrcKind:     true,
		otelAttrSrcIdentity: true,
		otelAttrDstKind:     true,
		otelAttrDstIdentity: true,
	}

	for _, key := range keys {
		if logOnly[key] {
			require.False(t, counted[key],
				"%q is log-only and must not become a Prometheus label", key)
			continue
		}
		require.True(t, counted[key],
			"emitted attribute %q is not counted by the chart's count connector", key)
	}
}
