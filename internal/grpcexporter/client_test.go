package grpcexporter

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
