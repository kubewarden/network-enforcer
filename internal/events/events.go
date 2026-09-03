// Package events wires the OTLP log exporter for
// policy_violation_acknowledged records. Mirrors runtime-enforcer.
package events

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc/credentials"

	"github.com/kubewarden/network-enforcer/internal/tlsutil"
)

// OTELConfig holds the configuration for the OTLP log exporter.
type OTELConfig struct {
	// Endpoint is the OTLP collector endpoint (host:port).
	Endpoint string
	// Protocol is the OTLP protocol: "grpc" or "http/protobuf".
	Protocol string
	// CACert is the path to the CA certificate for verifying the collector's TLS cert.
	// Empty means insecure.
	CACert string
	// ClientCert is the path to the client TLS certificate for mTLS.
	ClientCert string
	// ClientKey is the path to the client TLS key for mTLS.
	ClientKey string
}

type protocol string

const (
	protocolGRPC         protocol = "grpc"
	protocolHTTPProtobuf protocol = "http/protobuf"
)

func stringToProtocol(s string) (protocol, error) {
	switch s {
	case "grpc":
		return protocolGRPC, nil
	case "http/protobuf":
		return protocolHTTPProtobuf, nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", s)
	}
}

func createGRPCExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdklog.Exporter, error) {
	// Strip any http(s) prefix, WithEndpoint expects host:port.
	gRPCEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	insecure := caCertPath == ""
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(gRPCEndpoint),
	}
	if insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	} else {
		tlsConfig, err := tlsutil.ClientTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}
	return otlploggrpc.New(ctx, opts...)
}

func createHTTPExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdklog.Exporter, error) {
	// Strip any scheme prefix; WithEndpoint expects host:port.
	httpEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(httpEndpoint),
	}

	// Empty CA means insecure (matches gRPC behaviour and Init doc comment).
	// An explicit http:// scheme also opts into insecure.
	if caCertPath == "" || strings.HasPrefix(endpoint, "http://") {
		opts = append(opts, otlploghttp.WithInsecure())
	} else {
		tlsConfig, err := tlsutil.ClientTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsConfig))
	}
	return otlploghttp.New(ctx, opts...)
}

// Init returns an OTLP log logger for the given config.
// The caller must call shutdown to flush buffered records on exit.
func Init(
	ctx context.Context,
	cfg OTELConfig,
) (otellog.Logger, func(context.Context) error, error) {
	// Client certs without a CA are silently ignored by the exporters.
	// Reject the combination up front so users don't think mTLS is active.
	if cfg.CACert == "" && (cfg.ClientCert != "" || cfg.ClientKey != "") {
		return nil, nil, errors.New("client certificate requires a CA certificate (caCertPath is empty)")
	}

	var exporter sdklog.Exporter
	proto, err := stringToProtocol(cfg.Protocol)
	if err != nil {
		return nil, nil, err
	}
	switch proto {
	case protocolGRPC:
		exporter, err = createGRPCExporter(ctx, cfg.Endpoint, cfg.CACert, cfg.ClientCert, cfg.ClientKey)
	case protocolHTTPProtobuf:
		exporter, err = createHTTPExporter(ctx, cfg.Endpoint, cfg.CACert, cfg.ClientCert, cfg.ClientKey)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	logger := provider.Logger("network-enforcer")
	return logger, provider.Shutdown, nil
}
