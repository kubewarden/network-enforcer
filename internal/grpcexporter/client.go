package grpcexporter

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

// defaultScrapeTimeout bounds a single scrape RPC.
const defaultScrapeTimeout = 30 * time.Second

// AgentClientAPI is the controller's view of one agent. It allows mocking the
// client in tests.
type AgentClientAPI interface {
	ScrapeEvents(ctx context.Context) ([]*agentv1.Event, error)
	GetStatus(ctx context.Context) (*agentv1.GetStatusResponse, error)
	Close() error
}

// AgentFactoryConfig configures [AgentClientFactory]. The agent-hop client
// certificate is mounted as a directory (CSI or Secret volume), so only the
// directory path is needed. See ADR 0001.
type AgentFactoryConfig struct {
	// MTLSEnabled requires mutual TLS. Disable it only for local development.
	MTLSEnabled bool
	// CertDirPath holds tls.crt, tls.key, and ca.crt when MTLSEnabled is true.
	CertDirPath string
	// Timeout bounds a single scrape RPC. Zero uses [defaultScrapeTimeout].
	Timeout time.Duration
}

// AgentClientFactory creates agent clients. It rebuilds transport credentials
// on every dial so the controller picks up certificate rotation.
type AgentClientFactory struct {
	mtlsEnabled bool
	certDirPath string
	timeout     time.Duration
}

// NewAgentClientFactory returns a factory for conf. It checks the cert
// directory once when mTLS is enabled so a bad mount fails fast.
func NewAgentClientFactory(conf AgentFactoryConfig) (*AgentClientFactory, error) {
	timeout := conf.Timeout
	if timeout == 0 {
		timeout = defaultScrapeTimeout
	}
	if conf.MTLSEnabled {
		// Build the credentials once so the CA certificate is validated too,
		// not only the key pair. A bad mount then fails fast at startup. The
		// server name is irrelevant to loading the material, so it is empty
		// here; the real agent name is supplied on each dial.
		if _, err := tlsutil.ClientCredentials(conf.CertDirPath, ""); err != nil {
			return nil, fmt.Errorf("invalid agent client cert dir: %w", err)
		}
	}
	return &AgentClientFactory{
		mtlsEnabled: conf.MTLSEnabled,
		certDirPath: conf.CertDirPath,
		timeout:     timeout,
	}, nil
}

// Dial connects to the agent at endpoint. serverName is the agent's expected
// TLS identity, used for SNI and certificate hostname verification.
func (f *AgentClientFactory) Dial(_ context.Context, endpoint, serverName string) (*AgentClient, error) {
	creds, err := f.connCredentials(serverName)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create agent client for %s: %w", endpoint, err)
	}
	return &AgentClient{
		conn:    conn,
		client:  agentv1.NewAgentServiceClient(conn),
		timeout: f.timeout,
	}, nil
}

// connCredentials reloads the certificate directory on every dial so the
// controller picks up certificate rotation.
func (f *AgentClientFactory) connCredentials(serverName string) (credentials.TransportCredentials, error) {
	if !f.mtlsEnabled {
		return insecure.NewCredentials(), nil
	}
	return tlsutil.ClientCredentials(f.certDirPath, serverName)
}

// AgentClient scrapes one agent over gRPC.
type AgentClient struct {
	conn    *grpc.ClientConn
	client  agentv1.AgentServiceClient
	timeout time.Duration
}

// ScrapeEvents drains the agent's event buffer.
func (c *AgentClient) ScrapeEvents(ctx context.Context) ([]*agentv1.Event, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.ScrapeEvents(ctx, &agentv1.ScrapeEventsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to scrape events: %w", err)
	}
	return resp.GetEvents(), nil
}

// GetStatus reads the agent's buffer status.
func (c *AgentClient) GetStatus(ctx context.Context) (*agentv1.GetStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.GetStatus(ctx, &agentv1.GetStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to get agent status: %w", err)
	}
	return resp, nil
}

// Close releases the underlying connection.
func (c *AgentClient) Close() error {
	return c.conn.Close()
}

var _ AgentClientAPI = (*AgentClient)(nil)
