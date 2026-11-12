package grpcexporter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

const controllerSAN = "network-enforcer-controller"

type stubService struct {
	agentv1.UnimplementedAgentServiceServer
}

func (stubService) ScrapeEvents(
	context.Context,
	*agentv1.ScrapeEventsRequest,
) (*agentv1.ScrapeEventsResponse, error) {
	return &agentv1.ScrapeEventsResponse{
		Events: []*agentv1.Event{{RawRecord: []byte("event")}},
	}, nil
}

func TestServerServesAgentServiceOverMTLS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		clientSAN string
		wantErr   bool
	}{
		{name: "matching controller SAN accepted", clientSAN: controllerSAN, wantErr: false},
		{name: "wrong client SAN rejected", clientSAN: "intruder", wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			ca := newTestCA(t)
			serverDir := t.TempDir()
			clientDir := t.TempDir()
			ca.writeLeaf(t, serverDir, "agent-pod", x509.ExtKeyUsageServerAuth)
			ca.writeLeaf(t, clientDir, c.clientSAN, x509.ExtKeyUsageClientAuth)

			addr := startTestServer(t, ServerConfig{
				MTLSEnabled:       true,
				CertDirPath:       serverDir,
				ExpectedClientSAN: controllerSAN,
			})

			clientCreds, err := tlsutil.ClientCredentials(clientDir, "agent-pod")
			require.NoError(t, err)
			err = callScrapeEvents(t, addr, grpc.WithTransportCredentials(clientCreds))
			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestServerServesPlaintextWhenMTLSDisabled(t *testing.T) {
	t.Parallel()

	addr := startTestServer(t, ServerConfig{MTLSEnabled: false})

	err := callScrapeEvents(t, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
}

func TestServerShutdownNotBlockedByPendingConnection(t *testing.T) {
	t.Parallel()

	srv, err := NewServer(ServerConfig{MTLSEnabled: false}, stubService{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, lis) }()

	// Open a raw connection and send nothing. The connection stays in the
	// handshake, so a stop that waits on it would block past the budget.
	raw, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	cancel()

	select {
	case err = <-serveErr:
		require.NoError(t, err)
	case <-time.After(gracefulStopTimeout + 5*time.Second):
		t.Fatal("Serve did not return within the shutdown budget")
	}
}

func startTestServer(t *testing.T, conf ServerConfig) string {
	t.Helper()

	srv, err := NewServer(conf, stubService{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, lis) }()
	t.Cleanup(func() {
		cancel()
		<-serveErr
	})
	return lis.Addr().String()
}

func callScrapeEvents(t *testing.T, addr string, opt grpc.DialOption) error {
	t.Helper()

	conn, err := grpc.NewClient(addr, opt)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = agentv1.NewAgentServiceClient(conn).ScrapeEvents(ctx, &agentv1.ScrapeEventsRequest{})
	return err
}

type testCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	caPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{
		cert:  cert,
		key:   key,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *testCA) writeLeaf(t *testing.T, dir, san string, usage x509.ExtKeyUsage) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{Organization: []string{"Test Leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{san},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CAFile), ca.caPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CertFile), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.KeyFile), keyPEM, 0o600))
	assert.FileExists(t, filepath.Join(dir, tlsutil.CertFile))
}
