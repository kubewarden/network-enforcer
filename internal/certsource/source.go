package certsource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
)

// DirSource reads tls.crt, tls.key, and ca.crt from a mounted directory.
type DirSource struct {
	dir string
}

// NewDirSource returns a Source that reads PEM files from dir.
func NewDirSource(dir string) (*DirSource, error) {
	if dir == "" {
		return nil, errors.New("certificate directory is empty")
	}
	return &DirSource{dir: dir}, nil
}

// Get reads the certificate files from the directory.
func (s *DirSource) Get(ctx context.Context) ([]byte, []byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	certPath := filepath.Join(s.dir, tlsutil.CertFile)
	keyPath := filepath.Join(s.dir, tlsutil.KeyFile)
	caPath := filepath.Join(s.dir, tlsutil.CAFile)

	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read certificate %s: %w", certPath, err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read key %s: %w", keyPath, err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read CA certificate %s: %w", caPath, err)
	}
	return ca, cert, key, nil
}

// SecretSource reads a Secret (and optionally a CA ConfigMap) through a
// client.Reader. Pass mgr.GetAPIReader() so the manager does not start a
// cluster-wide Secret informer.
type SecretSource struct {
	reader      client.Reader
	secret      types.NamespacedName
	caConfigMap types.NamespacedName
}

// NewSecretSource returns a Source that reads PEM material from the API server.
// secret must be "namespace/name". caConfigMap is an optional "namespace/name"
// ConfigMap whose ca.crt key is used as the CA bundle.
func NewSecretSource(reader client.Reader, secret, caConfigMap string) (*SecretSource, error) {
	if reader == nil {
		return nil, errors.New("API reader is required")
	}
	secretName, err := ParseNamespacedName(secret)
	if err != nil {
		return nil, fmt.Errorf("certificate secret: %w", err)
	}
	src := &SecretSource{
		reader: reader,
		secret: secretName,
	}
	if caConfigMap != "" {
		caName, caErr := ParseNamespacedName(caConfigMap)
		if caErr != nil {
			return nil, fmt.Errorf("CA configmap: %w", caErr)
		}
		src.caConfigMap = caName
	}
	return src, nil
}

// Get reads the Secret (and optional CA ConfigMap) from the API server.
func (s *SecretSource) Get(ctx context.Context) ([]byte, []byte, []byte, error) {
	secret := &corev1.Secret{}
	if err := s.reader.Get(ctx, s.secret, secret); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get Secret %s: %w", s.secret.String(), err)
	}
	cert, err := secretKey(secret, tlsutil.CertFile)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := secretKey(secret, tlsutil.KeyFile)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.caConfigMap != (types.NamespacedName{}) {
		ca, caErr := s.caFromConfigMap(ctx)
		if caErr != nil {
			return nil, nil, nil, caErr
		}
		return ca, cert, key, nil
	}
	ca, err := secretKey(secret, tlsutil.CAFile)
	if err != nil {
		return nil, nil, nil, err
	}
	return ca, cert, key, nil
}

func (s *SecretSource) caFromConfigMap(ctx context.Context) ([]byte, error) {
	cm := &corev1.ConfigMap{}
	if err := s.reader.Get(ctx, s.caConfigMap, cm); err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s: %w", s.caConfigMap.String(), err)
	}
	if value, ok := cm.Data[tlsutil.CAFile]; ok && value != "" {
		return []byte(value), nil
	}
	if value, ok := cm.BinaryData[tlsutil.CAFile]; ok && len(value) > 0 {
		return bytes.Clone(value), nil
	}
	return nil, fmt.Errorf("configmap %s is missing key %q", s.caConfigMap.String(), tlsutil.CAFile)
}

func secretKey(secret *corev1.Secret, key string) ([]byte, error) {
	value, ok := secret.Data[key]
	if !ok || len(value) == 0 {
		return nil, fmt.Errorf("secret %s/%s is missing key %q", secret.Namespace, secret.Name, key)
	}
	return bytes.Clone(value), nil
}
