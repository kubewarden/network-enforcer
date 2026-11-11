package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
)

func TestServerCredentialsReloadsMaterialOnHandshake(t *testing.T) {
	t.Parallel()

	serverDir := t.TempDir()
	clientDir := t.TempDir()

	ca1, server1, client1 := generateMTLSMaterial(t, 1)
	writeCertDir(t, serverDir, ca1.caPEM, server1.certPEM, server1.keyPEM)
	writeCertDir(t, clientDir, ca1.caPEM, client1.certPEM, client1.keyPEM)

	creds, err := ServerCredentials(serverDir)
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	handshakeCh := make(chan error, 1)
	go func() {
		for {
			conn, acceptErr := lis.Accept()
			if acceptErr != nil {
				return
			}
			_, _, hsErr := creds.ServerHandshake(conn)
			_ = conn.Close()
			select {
			case handshakeCh <- hsErr:
			default:
			}
		}
	}()

	addr := lis.Addr().String()
	require.NoError(t, clientHandshake(t, addr, clientDir))
	require.NoError(t, <-handshakeCh)

	ca2, server2, client2 := generateMTLSMaterial(t, 2)
	writeCertDir(t, serverDir, ca2.caPEM, server2.certPEM, server2.keyPEM)
	writeCertDir(t, clientDir, ca2.caPEM, client2.certPEM, client2.keyPEM)

	require.NoError(t, clientHandshake(t, addr, clientDir),
		"handshake after rotating mounted certs should succeed without restarting the server")
	require.NoError(t, <-handshakeCh)
}

func TestServerCredentialsPinsClientSAN(t *testing.T) {
	t.Parallel()

	const expected = "network-enforcer-controller"
	cases := []struct {
		name        string
		clientSAN   []string
		expectedSAN string
		wantErr     bool
	}{
		{name: "matching SAN accepted", clientSAN: []string{expected}, expectedSAN: expected, wantErr: false},
		{name: "wrong SAN rejected", clientSAN: []string{"someone-else"}, expectedSAN: expected, wantErr: true},
		{name: "missing SAN rejected", clientSAN: nil, expectedSAN: expected, wantErr: true},
		{name: "empty expected stays chain-only", clientSAN: nil, expectedSAN: "", wantErr: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			serverDir := t.TempDir()
			clientDir := t.TempDir()

			ca, server, _ := generateMTLSMaterial(t, 1)
			client := issueLeaf(t, ca, 999,
				[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, c.clientSAN, nil)
			writeCertDir(t, serverDir, ca.caPEM, server.certPEM, server.keyPEM)
			writeCertDir(t, clientDir, ca.caPEM, client.certPEM, client.keyPEM)

			creds, err := ServerCredentials(serverDir, WithExpectedClientSAN(c.expectedSAN))
			require.NoError(t, err)

			serverErr := serverSideHandshake(t, creds, clientDir)
			if c.wantErr {
				require.Error(t, serverErr)
				return
			}
			require.NoError(t, serverErr)
		})
	}
}

// serverSideHandshake runs one mTLS handshake and returns the server-side
// handshake error. The client dials with the material under clientDir.
func serverSideHandshake(t *testing.T, creds credentials.TransportCredentials, clientDir string) error {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	handshakeCh := make(chan error, 1)
	go func() {
		conn, acceptErr := lis.Accept()
		if acceptErr != nil {
			handshakeCh <- acceptErr
			return
		}
		_, _, hsErr := creds.ServerHandshake(conn)
		_ = conn.Close()
		handshakeCh <- hsErr
	}()

	_ = clientHandshake(t, lis.Addr().String(), clientDir)
	return <-handshakeCh
}

func clientHandshake(t *testing.T, addr, clientDir string) error {
	t.Helper()
	clientCreds, err := ClientCredentials(clientDir, "localhost")
	require.NoError(t, err)

	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tlsConn, _, err := clientCreds.ClientHandshake(ctx, "localhost", raw)
	if err != nil {
		return err
	}
	return tlsConn.Close()
}

type mtlsLeaf struct {
	certPEM []byte
	keyPEM  []byte
}

type mtlsCA struct {
	caPEM []byte
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
}

func generateMTLSMaterial(t *testing.T, serialBase int64) (mtlsCA, mtlsLeaf, mtlsLeaf) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(serialBase),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
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
	ca := mtlsCA{
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		key:   caKey,
		cert:  caCert,
	}

	server := issueLeaf(t, ca, serialBase+10, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	client := issueLeaf(t, ca, serialBase+20, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	return ca, server, client
}

func issueLeaf(
	t *testing.T,
	ca mtlsCA,
	serial int64,
	ext []x509.ExtKeyUsage,
	dns []string,
	ips []net.IP,
) mtlsLeaf {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{Organization: []string{"Test Leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ext,
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca.cert, &leafKey.PublicKey, ca.key)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	return mtlsLeaf{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	}
}

func writeCertDir(t *testing.T, dir string, caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, CAFile), caPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, CertFile), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, KeyFile), keyPEM, 0o600))
}
