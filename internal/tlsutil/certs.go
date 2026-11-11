package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/grpc/credentials"
)

const (
	// CertFile is the standard file name for a TLS certificate.
	CertFile = "tls.crt"
	// KeyFile is the standard file name for a TLS private key.
	KeyFile = "tls.key"
	// CAFile is the standard file name for a CA certificate.
	CAFile = "ca.crt"
)

// LoadCACertPoolFromPEM parses PEM-encoded CA certificates and returns an
// [x509.CertPool] containing them.
func LoadCACertPoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificate from PEM")
	}
	return pool, nil
}

// LoadCACertPool reads PEM-encoded CA certificates from the given path and
// returns an [x509.CertPool] containing it.
// It supports certificate rotation when called on each handshake.
func LoadCACertPool(path string) (*x509.CertPool, error) {
	caPem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate %s: %w", path, err)
	}
	pool, err := LoadCACertPoolFromPEM(caPem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate from %s: %w", path, err)
	}
	return pool, nil
}

// LoadKeyPairFromPEM parses a TLS certificate and private key from PEM bytes.
func LoadKeyPairFromPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load key pair from PEM: %w", err)
	}
	return cert, nil
}

// LoadKeyPair loads a TLS certificate and private key from the given paths.
func LoadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load key pair (%s, %s): %w", certPath, keyPath, err)
	}
	return cert, nil
}

// ValidateCertDir checks that dirPath exists and contains a loadable TLS key
// pair (tls.crt + tls.key). It is intended for fail-fast validation at
// startup before any connections are attempted.
func ValidateCertDir(dirPath string) error {
	if dirPath == "" {
		return errors.New("certificate directory path is empty")
	}
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return fmt.Errorf("certificate directory does not exist: %w", err)
	}
	_, err := LoadKeyPair(
		filepath.Join(dirPath, CertFile),
		filepath.Join(dirPath, KeyFile),
	)
	return err
}

// ServerCredentialsFromPEM creates gRPC transport credentials for server-side
// mTLS from PEM-encoded material.
func ServerCredentialsFromPEM(caPEM, certPEM, keyPEM []byte) (credentials.TransportCredentials, error) {
	serverCert, err := LoadKeyPairFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}

	caPool, err := LoadCACertPoolFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate pool: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}
	return credentials.NewTLS(tlsConfig), nil
}

// ServerOption configures [ServerCredentials].
type ServerOption func(*serverOptions)

type serverOptions struct {
	expectedClientSAN string
}

// WithExpectedClientSAN pins the identity the client certificate must carry.
// The client leaf must present san as a DNS SAN; a certificate that only
// chains to the CA is rejected. An empty san keeps chain-only verification.
//
// RFC 0006 requires the agent to verify the controller's identity, not only
// that its certificate chains to the CA.
func WithExpectedClientSAN(san string) ServerOption {
	return func(o *serverOptions) {
		o.expectedClientSAN = san
	}
}

// ServerCredentials creates gRPC transport credentials for server-side mTLS.
// The server certificate, key, and CA under certDir are re-read on every
// handshake so cert-manager CSI (and Secret) rotation works without restarting
// the process.
func ServerCredentials(certDir string, opts ...ServerOption) (credentials.TransportCredentials, error) {
	var cfg serverOptions
	for _, opt := range opts {
		opt(&cfg)
	}

	if err := ValidateCertDir(certDir); err != nil {
		return nil, fmt.Errorf("invalid cert dir: %w", err)
	}
	caPath := filepath.Join(certDir, CAFile)
	certPath := filepath.Join(certDir, CertFile)
	keyPath := filepath.Join(certDir, KeyFile)

	// Fail fast at startup before any connections are accepted.
	if _, err := LoadCACertPool(caPath); err != nil {
		return nil, err
	}

	verifyClientSAN := clientSANVerifier(cfg.expectedClientSAN)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			caPool, err := LoadCACertPool(caPath)
			if err != nil {
				return nil, err
			}
			serverCert, err := LoadKeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:       tls.VersionTLS13,
				ClientAuth:       tls.RequireAndVerifyClientCert,
				ClientCAs:        caPool,
				Certificates:     []tls.Certificate{serverCert},
				VerifyConnection: verifyClientSAN,
			}, nil
		},
	}
	return credentials.NewTLS(tlsConfig), nil
}

// clientSANVerifier returns a [tls.Config.VerifyConnection] callback that checks
// the client leaf carries expectedSAN as a DNS SAN. It returns nil when
// expectedSAN is empty, which keeps chain-only verification. VerifyConnection
// also runs on resumed sessions, so the identity check is not bypassed.
// See RFC 0006.
func clientSANVerifier(expectedSAN string) func(tls.ConnectionState) error {
	if expectedSAN == "" {
		return nil
	}
	return func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			return errors.New("no verified client certificate chain")
		}
		leaf := state.VerifiedChains[0][0]
		if err := leaf.VerifyHostname(expectedSAN); err != nil {
			return fmt.Errorf("client certificate identity %q not allowed: %w", expectedSAN, err)
		}
		return nil
	}
}

// ClientCredentialsFromPEM creates gRPC transport credentials for client-side
// mTLS from PEM-encoded material. serverName is used for TLS SNI and
// certificate hostname verification.
func ClientCredentialsFromPEM(
	caPEM, certPEM, keyPEM []byte,
	serverName string,
) (credentials.TransportCredentials, error) {
	pool, err := LoadCACertPoolFromPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate pool: %w", err)
	}

	clientCert, err := LoadKeyPairFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load client key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
	}
	return credentials.NewTLS(tlsConfig), nil
}

// ClientCredentials creates gRPC transport credentials for client-side mTLS.
// It loads the client certificate and key, and configures server certificate
// verification against the CA pool. The serverName is used for TLS SNI and
// certificate hostname verification.
func ClientCredentials(certDir, serverName string) (credentials.TransportCredentials, error) {
	caPEM, certPEM, keyPEM, err := readCertDirPEMs(certDir)
	if err != nil {
		return nil, err
	}
	return ClientCredentialsFromPEM(caPEM, certPEM, keyPEM, serverName)
}

func readCertDirPEMs(certDir string) ([]byte, []byte, []byte, error) {
	if err := ValidateCertDir(certDir); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid cert dir: %w", err)
	}

	certPath := filepath.Join(certDir, CertFile)
	keyPath := filepath.Join(certDir, KeyFile)
	caPath := filepath.Join(certDir, CAFile)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read certificate %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read key %s: %w", keyPath, err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read CA certificate %s: %w", caPath, err)
	}
	return caPEM, certPEM, keyPEM, nil
}
