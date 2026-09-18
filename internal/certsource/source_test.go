package certsource

import (
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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
)

func generateCertPEMs(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	keyBytes, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return caPEM, certPEM, keyPEM
}

func writeCertDir(t *testing.T, caPEM, certPEM, keyPEM []byte) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CAFile), caPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CertFile), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.KeyFile), keyPEM, 0o600))
	return dir
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	return scheme
}

func tlsSecret(namespace, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		Namespace: namespace,
		Name:      name,
		Data:      data,
	}
}

func tlsConfigMap(namespace, name, ca string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		Namespace: namespace,
		Name:      name,
		Data:      map[string]string{tlsutil.CAFile: ca},
	}
}

func TestDirSource(t *testing.T) {
	t.Parallel()

	ca, cert, key := generateCertPEMs(t)

	tests := []struct {
		name    string
		dir     func(t *testing.T) string
		wantErr bool
		wantCA  []byte
		wantCrt []byte
		wantKey []byte
	}{
		{
			name: "reads tls material",
			dir: func(t *testing.T) string {
				t.Helper()
				return writeCertDir(t, ca, cert, key)
			},
			wantCA:  ca,
			wantCrt: cert,
			wantKey: key,
		},
		{
			name: "missing files",
			dir: func(t *testing.T) string {
				t.Helper()
				return t.TempDir()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src, err := NewDirSource(tt.dir(t))
			require.NoError(t, err)

			gotCA, gotCert, gotKey, err := src.Get(t.Context())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantCA, gotCA)
			require.Equal(t, tt.wantCrt, gotCert)
			require.Equal(t, tt.wantKey, gotKey)
		})
	}
}

func TestDirSourceCARotation(t *testing.T) {
	t.Parallel()

	ca1, cert, key := generateCertPEMs(t)
	ca2, _, _ := generateCertPEMs(t)
	require.NotEqual(t, ca1, ca2)

	dir := writeCertDir(t, ca1, cert, key)
	src, err := NewDirSource(dir)
	require.NoError(t, err)

	gotCA, gotCert, gotKey, err := src.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, ca1, gotCA)
	require.Equal(t, cert, gotCert)
	require.Equal(t, key, gotKey)

	require.NoError(t, os.WriteFile(filepath.Join(dir, tlsutil.CAFile), ca2, 0o600))

	gotCA, gotCert, gotKey, err = src.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, ca2, gotCA)
	require.Equal(t, cert, gotCert)
	require.Equal(t, key, gotKey)
}

func TestSecretSource(t *testing.T) {
	t.Parallel()

	ca, cert, key := generateCertPEMs(t)
	scheme := testScheme(t)

	tests := []struct {
		name        string
		objects     []client.Object
		secret      string
		caConfigMap string
		wantErr     bool
		wantCA      []byte
		wantCrt     []byte
		wantKey     []byte
	}{
		{
			name: "reads material from secret",
			objects: []client.Object{
				tlsSecret("calico-system", "goldmane-key-pair", map[string][]byte{
					tlsutil.CAFile:   ca,
					tlsutil.CertFile: cert,
					tlsutil.KeyFile:  key,
				}),
			},
			secret:  "calico-system/goldmane-key-pair",
			wantCA:  ca,
			wantCrt: cert,
			wantKey: key,
		},
		{
			name: "reads CA from configmap",
			objects: []client.Object{
				tlsSecret("calico-system", "goldmane-key-pair", map[string][]byte{
					tlsutil.CertFile: cert,
					tlsutil.KeyFile:  key,
				}),
				tlsConfigMap("calico-system", "goldmane-ca-bundle", string(ca)),
			},
			secret:      "calico-system/goldmane-key-pair",
			caConfigMap: "calico-system/goldmane-ca-bundle",
			wantCA:      ca,
			wantCrt:     cert,
			wantKey:     key,
		},
		{
			name:    "missing secret",
			secret:  "calico-system/goldmane-key-pair",
			wantErr: true,
		},
		{
			name: "missing key",
			objects: []client.Object{
				tlsSecret("ns", "certs", map[string][]byte{tlsutil.CertFile: []byte("cert")}),
			},
			secret:  "ns/certs",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.objects...).Build()
			src, err := NewSecretSource(cl, tt.secret, tt.caConfigMap)
			require.NoError(t, err)

			gotCA, gotCert, gotKey, err := src.Get(t.Context())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantCA, gotCA)
			require.Equal(t, tt.wantCrt, gotCert)
			require.Equal(t, tt.wantKey, gotKey)
		})
	}
}

func TestSecretSourceCARotation(t *testing.T) {
	t.Parallel()

	ca1, cert, key := generateCertPEMs(t)
	ca2, _, _ := generateCertPEMs(t)
	require.NotEqual(t, ca1, ca2)

	const (
		namespace = "calico-system"
		name      = "goldmane-key-pair"
	)
	cl := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(
		tlsSecret(namespace, name, map[string][]byte{
			tlsutil.CAFile:   ca1,
			tlsutil.CertFile: cert,
			tlsutil.KeyFile:  key,
		}),
	).Build()
	src, err := NewSecretSource(cl, namespace+"/"+name, "")
	require.NoError(t, err)

	gotCA, gotCert, gotKey, err := src.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, ca1, gotCA)
	require.Equal(t, cert, gotCert)
	require.Equal(t, key, gotKey)

	secret := &corev1.Secret{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{Namespace: namespace, Name: name}, secret))
	secret.Data[tlsutil.CAFile] = ca2
	require.NoError(t, cl.Update(t.Context(), secret))

	gotCA, gotCert, gotKey, err = src.Get(t.Context())
	require.NoError(t, err)
	require.Equal(t, ca2, gotCA)
	require.Equal(t, cert, gotCert)
	require.Equal(t, key, gotKey)
}
