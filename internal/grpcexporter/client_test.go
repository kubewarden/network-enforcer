package grpcexporter

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

func TestAgentClientFactoryScrapesOverMTLS(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	serverDir := t.TempDir()
	controllerDir := t.TempDir()
	ca.writeLeaf(t, serverDir, "agent-pod", x509.ExtKeyUsageServerAuth)
	ca.writeLeaf(t, controllerDir, controllerSAN, x509.ExtKeyUsageClientAuth)
	addr := startTestServer(
		t,
		ServerConfig{MTLSEnabled: true, CertDirPath: serverDir, ExpectedClientSAN: controllerSAN},
	)
	factory, err := NewAgentClientFactory(AgentFactoryConfig{MTLSEnabled: true, CertDirPath: controllerDir})
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

func TestAgentClientFactoryRejectsWrongTLSIdentities(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		serverSAN      string
		clientSAN      string
		authority      string
		expectedClient string
	}{
		{
			name:           "wrong agent server authority",
			serverSAN:      "actual-agent",
			clientSAN:      controllerSAN,
			authority:      "expected-agent",
			expectedClient: controllerSAN,
		},
		{
			name:           "wrong controller client identity",
			serverSAN:      "agent-pod",
			clientSAN:      "intruder",
			authority:      "agent-pod",
			expectedClient: controllerSAN,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ca := newTestCA(t)
			serverDir, clientDir := t.TempDir(), t.TempDir()
			ca.writeLeaf(t, serverDir, tc.serverSAN, x509.ExtKeyUsageServerAuth)
			ca.writeLeaf(t, clientDir, tc.clientSAN, x509.ExtKeyUsageClientAuth)
			addr := startTestServer(
				t,
				ServerConfig{MTLSEnabled: true, CertDirPath: serverDir, ExpectedClientSAN: tc.expectedClient},
			)
			factory, err := NewAgentClientFactory(AgentFactoryConfig{MTLSEnabled: true, CertDirPath: clientDir})
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := factory.Dial(ctx, addr, tc.authority)
			require.NoError(t, err)
			defer client.Close()
			_, err = client.ScrapeEvents(ctx)
			require.Error(t, err)
		})
	}
}

func TestAgentClientFactoryReloadsCertificateDirectoryAfterFailure(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	serverDir, clientDir := t.TempDir(), t.TempDir()
	ca.writeLeaf(t, serverDir, "agent-pod", x509.ExtKeyUsageServerAuth)
	ca.writeLeaf(t, clientDir, controllerSAN, x509.ExtKeyUsageClientAuth)
	certPath := filepath.Join(clientDir, tlsutil.CertFile)
	originalCert, err := os.ReadFile(certPath)
	require.NoError(t, err)
	addr := startTestServer(
		t,
		ServerConfig{MTLSEnabled: true, CertDirPath: serverDir, ExpectedClientSAN: controllerSAN},
	)
	factory, err := NewAgentClientFactory(AgentFactoryConfig{MTLSEnabled: true, CertDirPath: clientDir})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certPath, []byte("invalid rotation"), 0o600))
	if _, err = factory.Dial(context.Background(), addr, "agent-pod"); err == nil {
		t.Fatal("expected invalid rotated certificate to fail dial")
	}
	require.NoError(t, os.WriteFile(certPath, originalCert, 0o600))
	client, err := factory.Dial(context.Background(), addr, "agent-pod")
	require.NoError(t, err)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.ScrapeEvents(ctx)
	require.NoError(t, err)
}

func TestAgentClientFactoryValidatesReceiveLimit(t *testing.T) {
	t.Parallel()
	_, err := NewAgentClientFactory(AgentFactoryConfig{MaxRecvMsgSize: -1})
	require.ErrorContains(t, err, "maximum receive message size must be positive")
}

func TestAgentClientFactoryAcceptsRepresentativeFullBatch(t *testing.T) {
	t.Parallel()
	addr := startLargeResponseTestServer(t, 10_000, 1024)
	factory, err := NewAgentClientFactory(AgentFactoryConfig{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := factory.Dial(ctx, addr, "agent-pod")
	require.NoError(t, err)
	defer client.Close()
	events, err := client.ScrapeEvents(ctx)
	require.NoError(t, err)
	assert.Len(t, events, 10_000)
	assert.Len(t, events[0].GetRawRecord(), 1024)
}

func TestAgentClientFactoryRejectsResponseAboveConfiguredLimit(t *testing.T) {
	t.Parallel()
	addr := startLargeResponseTestServer(t, 1, 2*1024*1024)
	factory, err := NewAgentClientFactory(AgentFactoryConfig{MaxRecvMsgSize: 1024 * 1024})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := factory.Dial(ctx, addr, "agent-pod")
	require.NoError(t, err)
	defer client.Close()
	_, err = client.ScrapeEvents(ctx)
	require.Error(t, err)
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

func TestNewAgentClientFactoryValidatesCA(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		writeCert func(t *testing.T, ca *testCA, dir string)
		wantErr   bool
	}{
		{name: "accepts a complete cert dir", writeCert: func(t *testing.T, ca *testCA, dir string) {
			ca.writeLeaf(t, dir, controllerSAN, x509.ExtKeyUsageClientAuth)
		}},
		{name: "rejects malformed CA", writeCert: func(t *testing.T, ca *testCA, dir string) {
			ca.writeLeaf(t, dir, controllerSAN, x509.ExtKeyUsageClientAuth)
			require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CAFile), []byte("not a certificate"), 0o600))
		}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tc.writeCert(t, newTestCA(t), dir)
			factory, err := NewAgentClientFactory(AgentFactoryConfig{MTLSEnabled: true, CertDirPath: dir})
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, factory)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, factory)
		})
	}
}

type largeResponseService struct {
	agentv1.UnimplementedAgentServiceServer

	eventCount int
	rawSize    int
}

func (s largeResponseService) ScrapeEvents(
	context.Context,
	*agentv1.ScrapeEventsRequest,
) (*agentv1.ScrapeEventsResponse, error) {
	events := make([]*agentv1.Event, s.eventCount)
	for i := range events {
		events[i] = &agentv1.Event{RawRecord: make([]byte, s.rawSize)}
	}
	return &agentv1.ScrapeEventsResponse{Events: events}, nil
}

func startLargeResponseTestServer(t *testing.T, eventCount, rawSize int) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	agentv1.RegisterAgentServiceServer(server, largeResponseService{eventCount: eventCount, rawSize: rawSize})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener.Addr().String()
}
