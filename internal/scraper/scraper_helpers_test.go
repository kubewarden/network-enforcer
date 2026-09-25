package scraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveTLSServerName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		endpoint    string
		override    string
		peer        string
		expected    string
		expectedErr string
	}{
		{
			name:     "explicit server name wins over the endpoint host",
			endpoint: "goldmane.calico-system.svc:7443",
			override: "goldmane.example.svc",
			peer:     "Goldmane",
			expected: "goldmane.example.svc",
		},
		{
			name:     "server name falls back to the endpoint host",
			endpoint: "hubble-relay.kube-system.svc:443",
			peer:     "Hubble Relay",
			expected: "hubble-relay.kube-system.svc",
		},
		{
			name:        "endpoint without a port and no override",
			endpoint:    "goldmane.calico-system.svc",
			peer:        "Goldmane",
			expectedErr: `invalid Goldmane endpoint "goldmane.calico-system.svc"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveTLSServerName(tc.endpoint, tc.override, tc.peer)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}
