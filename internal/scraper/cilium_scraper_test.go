package scraper

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubCertSource struct {
	ca, cert, key []byte
	err           error
	calls         int
}

func (s *stubCertSource) Get(context.Context) ([]byte, []byte, []byte, error) {
	s.calls++
	if s.err != nil {
		return nil, nil, nil, s.err
	}
	return s.ca, s.cert, s.key, nil
}

func newClientCertPEMs(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Hubble Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "network-enforcer.hubble-relay.cilium.io"},
		DNSNames:     []string{"network-enforcer.hubble-relay.cilium.io"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
}

func newTestCiliumScraper(conf CiliumScraperConfig) *CiliumScraper {
	conf.Logger = slog.New(slog.DiscardHandler)
	return NewCiliumScraper(conf)
}

func TestCiliumScraperTransportCredentialsInsecure(t *testing.T) {
	t.Parallel()

	scraper := newTestCiliumScraper(CiliumScraperConfig{
		Endpoint: "hubble-relay.kube-system.svc:80",
	})

	creds, err := scraper.transportCredentials(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "insecure", creds.Info().SecurityProtocol)
}

func TestCiliumScraperTransportCredentialsTLS(t *testing.T) {
	t.Parallel()

	ca, cert, key := newClientCertPEMs(t)
	source := &stubCertSource{ca: ca, cert: cert, key: key}
	scraper := newTestCiliumScraper(CiliumScraperConfig{
		Endpoint:      "hubble-relay.kube-system.svc:443",
		CertSource:    source,
		TLSServerName: "ui.hubble-relay.cilium.io",
	})

	creds, err := scraper.transportCredentials(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "tls", creds.Info().SecurityProtocol)
	assert.Equal(t, 1, source.calls)
}

// gRPC overwrites tls.Config.ServerName with the channel authority, so an override only works as the authority.
func TestCiliumScraperDialOptions(t *testing.T) {
	t.Parallel()

	ca, cert, key := newClientCertPEMs(t)

	tests := []struct {
		name             string
		conf             CiliumScraperConfig
		expectedOptCount int
	}{
		{
			name: "insecure hop carries credentials only",
			conf: CiliumScraperConfig{
				Endpoint: "hubble-relay.kube-system.svc:80",
			},
			expectedOptCount: 1,
		},
		{
			name: "server name override is also the authority",
			conf: CiliumScraperConfig{
				Endpoint:      "hubble-relay.kube-system.svc:443",
				CertSource:    &stubCertSource{ca: ca, cert: cert, key: key},
				TLSServerName: "ui.hubble-relay.cilium.io",
			},
			expectedOptCount: 2,
		},
		{
			name: "no override leaves the endpoint authority alone",
			conf: CiliumScraperConfig{
				Endpoint:   "hubble-relay.kube-system.svc:443",
				CertSource: &stubCertSource{ca: ca, cert: cert, key: key},
			},
			expectedOptCount: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			scraper := newTestCiliumScraper(test.conf)
			opts, err := scraper.dialOptions(context.Background())
			require.NoError(t, err)
			assert.Len(t, opts, test.expectedOptCount)
		})
	}
}

func TestCiliumScraperTransportCredentialsRotation(t *testing.T) {
	t.Parallel()

	ca1, cert, key := newClientCertPEMs(t)
	ca2, _, _ := newClientCertPEMs(t)
	require.NotEqual(t, ca1, ca2)

	source := &stubCertSource{ca: ca1, cert: cert, key: key}
	scraper := newTestCiliumScraper(CiliumScraperConfig{
		Endpoint:      "hubble-relay.kube-system.svc:443",
		CertSource:    source,
		TLSServerName: "ui.hubble-relay.cilium.io",
	})

	_, err := scraper.transportCredentials(context.Background())
	require.NoError(t, err)

	source.ca = ca2
	_, err = scraper.transportCredentials(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, source.calls)
}

func TestCiliumScraperTransportCredentialsErrors(t *testing.T) {
	t.Parallel()

	ca, cert, key := newClientCertPEMs(t)
	sourceErr := errors.New("secret not found")

	tests := []struct {
		name        string
		conf        CiliumScraperConfig
		expectedErr string
	}{
		{
			name: "cert source failure",
			conf: CiliumScraperConfig{
				Endpoint:      "hubble-relay.kube-system.svc:443",
				CertSource:    &stubCertSource{err: sourceErr},
				TLSServerName: "ui.hubble-relay.cilium.io",
			},
			expectedErr: "failed to obtain TLS material for Hubble Relay",
		},
		{
			name: "endpoint without a port and no server name override",
			conf: CiliumScraperConfig{
				Endpoint:   "hubble-relay.kube-system.svc",
				CertSource: &stubCertSource{ca: ca, cert: cert, key: key},
			},
			expectedErr: "invalid Hubble Relay endpoint",
		},
		{
			name: "unparseable material",
			conf: CiliumScraperConfig{
				Endpoint:      "hubble-relay.kube-system.svc:443",
				CertSource:    &stubCertSource{ca: []byte("not a pem"), cert: cert, key: key},
				TLSServerName: "ui.hubble-relay.cilium.io",
			},
			expectedErr: "failed to load TLS credentials for Hubble Relay",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			scraper := newTestCiliumScraper(test.conf)
			creds, err := scraper.transportCredentials(context.Background())
			require.ErrorContains(t, err, test.expectedErr)
			assert.Nil(t, creds)
		})
	}
}
