package grpcexporter

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
)

func TestAgentClientFactoryScrapesOverMTLS(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	serverDir := t.TempDir()
	controllerDir := t.TempDir()
	ca.writeLeaf(t, serverDir, "agent-pod", x509.ExtKeyUsageServerAuth)
	ca.writeLeaf(t, controllerDir, controllerSAN, x509.ExtKeyUsageClientAuth)

	addr := startTestServer(t, ServerConfig{
		MTLSEnabled:       true,
		CertDirPath:       serverDir,
		ExpectedClientSAN: controllerSAN,
	})

	factory, err := NewAgentClientFactory(AgentFactoryConfig{
		MTLSEnabled: true,
		CertDirPath: controllerDir,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := factory.Dial(ctx, addr, "agent-pod")
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	events, err := client.ScrapeEvents(ctx)
	require.NoError(t, err)
	assert.Len(t, events, 1)
}

func TestNewAgentClientFactoryValidatesCA(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		writeCert func(t *testing.T, ca *testCA, dir string)
		wantErr   bool
	}{
		{
			name: "accepts a complete cert dir",
			writeCert: func(t *testing.T, ca *testCA, dir string) {
				ca.writeLeaf(t, dir, controllerSAN, x509.ExtKeyUsageClientAuth)
			},
		},
		{
			name: "rejects a malformed ca.crt despite a valid key pair",
			writeCert: func(t *testing.T, ca *testCA, dir string) {
				ca.writeLeaf(t, dir, controllerSAN, x509.ExtKeyUsageClientAuth)
				require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CAFile), []byte("not a certificate"), 0o600))
			},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			c.writeCert(t, newTestCA(t), dir)

			factory, err := NewAgentClientFactory(AgentFactoryConfig{
				MTLSEnabled: true,
				CertDirPath: dir,
			})
			if c.wantErr {
				require.Error(t, err)
				require.Nil(t, factory)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, factory)
		})
	}
}

func TestAgentClientFactoryScrapesPlaintextWhenInsecure(t *testing.T) {
	t.Parallel()

	addr := startTestServer(t, ServerConfig{MTLSEnabled: false})

	factory, err := NewAgentClientFactory(AgentFactoryConfig{MTLSEnabled: false})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := factory.Dial(ctx, addr, "agent-pod")
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	events, err := client.ScrapeEvents(ctx)
	require.NoError(t, err)
	assert.Len(t, events, 1)
}
