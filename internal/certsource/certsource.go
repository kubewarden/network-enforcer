package certsource

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
)

// Mode is the TLS mode of a provider hop.
type Mode string

const (
	// ModeIssuer loads material from a directory populated by cert-manager CSI.
	ModeIssuer Mode = "issuer"
	// ModeExistingSecret loads material from a mounted directory or from a Secret.
	ModeExistingSecret Mode = "existingSecret"
	// ModeInsecure disables TLS for the provider hop.
	ModeInsecure Mode = "insecure"
)

// Source obtains PEM-encoded TLS material. Get must re-read on every call so
// callers pick up rotation without restarting the process.
type Source interface {
	// Get returns PEM-encoded CA, certificate, and private key.
	Get(ctx context.Context) (ca, cert, key []byte, err error)
}

// Config is the provider-neutral TLS flag combination.
type Config struct {
	// Mode is issuer, existingSecret, or insecure.
	Mode Mode
	// CertDir is the directory containing tls.crt, tls.key, and ca.crt.
	CertDir string
	// CertSecret is a namespace/name reference to a Secret.
	CertSecret string
	// CAConfigMap is an optional namespace/name reference to a CA bundle ConfigMap.
	CAConfigMap string
}

// New returns a [Source] for cfg.
//
// Issuer and a mounted existingSecret return a [DirSource].
// A cross-namespace existingSecret returns a [SecretSource] that reads through
// reader. Insecure mode is valid for [Validate] but has no source; callers
// should skip TLS instead of calling New.
func New(cfg Config, reader client.Reader) (Source, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	switch cfg.Mode {
	case ModeIssuer:
		return NewDirSource(cfg.CertDir)
	case ModeExistingSecret:
		if cfg.CertDir != "" {
			return NewDirSource(cfg.CertDir)
		}
		return NewSecretSource(reader, cfg.CertSecret, cfg.CAConfigMap)
	case ModeInsecure:
		return nil, fmt.Errorf("provider TLS mode %q has no certificate source", cfg.Mode)
	default:
		return nil, fmt.Errorf("unknown provider TLS mode %q", cfg.Mode)
	}
}

// ParseNamespacedName parses a "namespace/name" reference.
func ParseNamespacedName(value string) (types.NamespacedName, error) {
	namespace, name, found := strings.Cut(value, "/")
	if !found || namespace == "" || name == "" || strings.Contains(name, "/") {
		return types.NamespacedName{}, fmt.Errorf("expected namespace/name, got %q", value)
	}
	return types.NamespacedName{Namespace: namespace, Name: name}, nil
}

// Validate checks that the TLS flag combination is consistent.
func Validate(cfg Config) error {
	switch cfg.Mode {
	case ModeInsecure:
		if cfg.CertDir != "" || cfg.CertSecret != "" || cfg.CAConfigMap != "" {
			return fmt.Errorf(
				"provider TLS mode %q does not accept --provider-tls-cert-dir, --provider-tls-cert-secret, or --provider-tls-ca-configmap",
				cfg.Mode,
			)
		}
		return nil
	case ModeIssuer:
		return validateIssuer(cfg)
	case ModeExistingSecret:
		return validateExistingSecret(cfg)
	default:
		return fmt.Errorf("unknown provider TLS mode %q (want issuer, existingSecret, or insecure)", cfg.Mode)
	}
}

func validateIssuer(cfg Config) error {
	if cfg.CertDir == "" {
		return fmt.Errorf("provider TLS mode %q requires --provider-tls-cert-dir", cfg.Mode)
	}
	if cfg.CertSecret != "" || cfg.CAConfigMap != "" {
		return fmt.Errorf(
			"provider TLS mode %q does not accept --provider-tls-cert-secret or --provider-tls-ca-configmap",
			cfg.Mode,
		)
	}
	if err := tlsutil.ValidateCertDir(cfg.CertDir); err != nil {
		return fmt.Errorf("provider TLS cert dir: %w", err)
	}
	return nil
}

func validateExistingSecret(cfg Config) error {
	dirSet := cfg.CertDir != ""
	secretSet := cfg.CertSecret != ""
	if dirSet == secretSet {
		return fmt.Errorf(
			"provider TLS mode %q requires exactly one of --provider-tls-cert-dir or --provider-tls-cert-secret",
			cfg.Mode,
		)
	}
	if dirSet {
		if cfg.CAConfigMap != "" {
			return errors.New("--provider-tls-ca-configmap requires --provider-tls-cert-secret")
		}
		if err := tlsutil.ValidateCertDir(cfg.CertDir); err != nil {
			return fmt.Errorf("provider TLS cert dir: %w", err)
		}
		return nil
	}
	if _, err := ParseNamespacedName(cfg.CertSecret); err != nil {
		return fmt.Errorf("--provider-tls-cert-secret: %w", err)
	}
	if cfg.CAConfigMap != "" {
		if _, err := ParseNamespacedName(cfg.CAConfigMap); err != nil {
			return fmt.Errorf("--provider-tls-ca-configmap: %w", err)
		}
	}
	return nil
}
