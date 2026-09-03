package events_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/network-enforcer/internal/events"
)

func generateCACertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func generateClientKeyPair(t *testing.T, dir string) (string, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{Organization: []string{"Test Client"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writeFile(t, certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	keyBytes, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	writeFile(t, keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))

	return certPath, keyPath
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestInit_RejectsUnsupportedProtocol(t *testing.T) {
	t.Parallel()

	logger, shutdown, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint: "localhost:4317",
			Protocol: "smoke-signals",
		},
	)
	require.Error(t, err, "expected error for unsupported protocol")
	require.Nil(t, logger, "expected nil logger on error")
	require.Nil(t, shutdown, "expected nil shutdown on error")
}

func TestInit_GRPCInsecure(t *testing.T) {
	t.Parallel()

	logger, shutdown, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint: "localhost:4317",
			Protocol: "grpc",
		},
	)
	require.NoError(t, err, "unexpected error")
	require.NotNil(t, logger, "expected non-nil logger")
	require.NotNil(t, shutdown, "expected non-nil shutdown func")
	require.NoError(t, shutdown(context.Background()), "shutdown returned error")
}

func TestInit_GRPCmTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	writeFile(t, caPath, generateCACertPEM(t))
	certPath, keyPath := generateClientKeyPair(t, dir)

	logger, shutdown, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint:   "otel-collector:4317",
			Protocol:   "grpc",
			CACert:     caPath,
			ClientCert: certPath,
			ClientKey:  keyPath,
		},
	)
	require.NoError(t, err, "unexpected error with mTLS gRPC")
	require.NotNil(t, logger, "expected non-nil logger")
	require.NotNil(t, shutdown, "expected non-nil shutdown func")
	require.NoError(t, shutdown(context.Background()), "shutdown returned error")
}

func TestInit_GRPCmTLSMissingCA(t *testing.T) {
	t.Parallel()

	_, _, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint: "otel-collector:4317",
			Protocol: "grpc",
			CACert:   filepath.Join(t.TempDir(), "missing-ca.crt"),
		},
	)
	require.Error(t, err, "expected error for missing CA cert")
}

func TestInit_RejectsClientCertWithoutCA(t *testing.T) {
	t.Parallel()

	_, _, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint:   "localhost:4317",
			Protocol:   "grpc",
			ClientCert: "/some/cert.pem",
			ClientKey:  "/some/key.pem",
		},
	)
	require.Error(t, err, "expected error when client cert is set but CA is empty")
	require.Contains(t, err.Error(), "client certificate requires a CA certificate")
}

func TestInit_RejectsClientKeyWithoutCA(t *testing.T) {
	t.Parallel()

	_, _, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint:  "localhost:4317",
			Protocol:  "grpc",
			ClientKey: "/some/key.pem",
		},
	)
	require.Error(t, err, "expected error when client key is set but CA is empty")
	require.Contains(t, err.Error(), "client certificate requires a CA certificate")
}

func TestInit_HTTPProtobufInsecure(t *testing.T) {
	t.Parallel()

	logger, shutdown, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint: "http://localhost:4318",
			Protocol: "http/protobuf",
		},
	)
	require.NoError(t, err, "unexpected error")
	require.NotNil(t, logger, "expected non-nil logger")
	require.NotNil(t, shutdown, "expected non-nil shutdown func")
	require.NoError(t, shutdown(context.Background()), "shutdown returned error")
}

func TestInit_HTTPProtobufInsecureHostPort(t *testing.T) {
	t.Parallel()

	// host:port without scheme + empty CA should also be insecure
	// (not silently switch to HTTPS).
	logger, shutdown, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint: "localhost:4318",
			Protocol: "http/protobuf",
		},
	)
	require.NoError(t, err, "unexpected error for host:port endpoint without CA")
	require.NotNil(t, logger, "expected non-nil logger")
	require.NotNil(t, shutdown, "expected non-nil shutdown func")
	require.NoError(t, shutdown(context.Background()), "shutdown returned error")
}

func TestInit_HTTPProtobufmTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	writeFile(t, caPath, generateCACertPEM(t))
	certPath, keyPath := generateClientKeyPair(t, dir)

	logger, shutdown, err := events.Init(
		context.Background(), events.OTELConfig{
			Endpoint:   "https://otel-collector:4318",
			Protocol:   "http/protobuf",
			CACert:     caPath,
			ClientCert: certPath,
			ClientKey:  keyPath,
		},
	)
	require.NoError(t, err, "unexpected error with mTLS HTTP")
	require.NotNil(t, logger, "expected non-nil logger")
	require.NotNil(t, shutdown, "expected non-nil shutdown func")
	require.NoError(t, shutdown(context.Background()), "shutdown returned error")
}
