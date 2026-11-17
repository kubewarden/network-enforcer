package grpcexporter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kubewarden/network-enforcer/internal/certsource"
	"github.com/kubewarden/network-enforcer/internal/tlsutil"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

const (
	// defaultScrapeTimeout bounds a single scrape RPC.
	defaultScrapeTimeout = 30 * time.Second
	// DefaultAgentMaxRecvMsgSize bounds one drained response, not total process memory.
	DefaultAgentMaxRecvMsgSize = 16 * 1024 * 1024
)

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
	// MaxRecvMsgSize limits each response. Zero uses [DefaultAgentMaxRecvMsgSize].
	MaxRecvMsgSize int
}

// AgentClientFactory creates agent clients. It rebuilds transport credentials
// on every dial so the controller picks up certificate rotation.
type AgentClientFactory struct {
	mtlsEnabled    bool
	timeout        time.Duration
	maxRecvMsgSize int
	source         *certsource.DirSource
}

// NewAgentClientFactory returns a factory for conf. It checks the cert
// directory once when mTLS is enabled so a bad mount fails fast.
func NewAgentClientFactory(conf AgentFactoryConfig) (*AgentClientFactory, error) {
	timeout := conf.Timeout
	if timeout == 0 {
		timeout = defaultScrapeTimeout
	}
	maxRecvMsgSize := conf.MaxRecvMsgSize
	if maxRecvMsgSize == 0 {
		maxRecvMsgSize = DefaultAgentMaxRecvMsgSize
	}
	if maxRecvMsgSize < 0 {
		return nil, errors.New("agent gRPC maximum receive message size must be positive")
	}
	var source *certsource.DirSource
	if conf.MTLSEnabled {
		var err error
		source, err = certsource.NewDirSource(conf.CertDirPath)
		if err != nil {
			return nil, fmt.Errorf("invalid agent client cert dir: %w", err)
		}
		// Validate the real certificate, key and CA at startup. Dial reloads
		// the directory so CSI rotations take effect on the next poll.
		caPEM, certPEM, keyPEM, err := source.Get(context.Background())
		if err != nil {
			return nil, fmt.Errorf("invalid agent client cert dir: %w", err)
		}
		if _, err = tlsutil.ClientCredentialsFromPEM(caPEM, certPEM, keyPEM, ""); err != nil {
			return nil, fmt.Errorf("invalid agent client cert dir: %w", err)
		}
	}
	return &AgentClientFactory{
		mtlsEnabled:    conf.MTLSEnabled,
		timeout:        timeout,
		maxRecvMsgSize: maxRecvMsgSize,
		source:         source,
	}, nil
}

// Dial connects to the agent at endpoint. authority is the expected agent
// identity and is used by gRPC for TLS verification and HTTP/2 authority.
func (f *AgentClientFactory) Dial(ctx context.Context, endpoint, authority string) (*AgentClient, error) {
	creds, err := f.connCredentials(ctx)
	if err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithAuthority(authority),
	}
	if f.maxRecvMsgSize > 0 {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(f.maxRecvMsgSize)))
	}
	conn, err := grpc.NewClient(endpoint, opts...)
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
// controller picks up certificate rotation. The server name is intentionally
// blank; Dial supplies the Pod DNS identity through grpc.WithAuthority.
func (f *AgentClientFactory) connCredentials(ctx context.Context) (credentials.TransportCredentials, error) {
	if !f.mtlsEnabled {
		return insecure.NewCredentials(), nil
	}
	caPEM, certPEM, keyPEM, err := f.source.Get(ctx)
	if err != nil {
		return nil, err
	}
	return tlsutil.ClientCredentialsFromPEM(caPEM, certPEM, keyPEM, "")
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
