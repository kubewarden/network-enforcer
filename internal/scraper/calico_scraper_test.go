package scraper

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCalicoScraper(conf CalicoScraperConfig) *CalicoScraper {
	conf.Logger = slog.New(slog.DiscardHandler)
	return NewCalicoScraper(conf)
}

func TestCalicoScraperDialOptions(t *testing.T) {
	t.Parallel()

	ca, cert, key := newClientCertPEMs(t)

	cases := []struct {
		name             string
		conf             CalicoScraperConfig
		expectedOptCount int
		wantErr          string
	}{
		{
			name: "credentials only without override",
			conf: CalicoScraperConfig{
				Endpoint:   "goldmane.calico-system.svc:7443",
				CertSource: &stubCertSource{ca: ca, cert: cert, key: key},
			},
			expectedOptCount: 1,
		},
		{
			name: "server name override is also the authority",
			conf: CalicoScraperConfig{
				Endpoint:      "goldmane.calico-system.svc:7443",
				CertSource:    &stubCertSource{ca: ca, cert: cert, key: key},
				TLSServerName: "goldmane.example.svc",
			},
			expectedOptCount: 2,
		},
		{
			name: "nil cert source",
			conf: CalicoScraperConfig{
				Endpoint: "goldmane.calico-system.svc:7443",
			},
			wantErr: "goldmane requires TLS credentials",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scraper := newTestCalicoScraper(tc.conf)
			opts, err := scraper.dialOptions(context.Background())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Nil(t, opts)
				return
			}
			require.NoError(t, err)
			assert.Len(t, opts, tc.expectedOptCount)
		})
	}
}

func TestCalicoScraperNewGoldmaneClient(t *testing.T) {
	t.Parallel()

	ca, cert, key := newClientCertPEMs(t)
	sourceErr := errors.New("secret not found")

	cases := []struct {
		name      string
		conf      CalicoScraperConfig
		wantErr   string
		wantCalls int
	}{
		{
			name: "nil cert source",
			conf: CalicoScraperConfig{
				Endpoint: "goldmane.calico-system.svc:7443",
			},
			wantErr: "goldmane requires TLS credentials",
		},
		{
			name: "endpoint without a port",
			conf: CalicoScraperConfig{
				Endpoint:   "goldmane.calico-system.svc",
				CertSource: &stubCertSource{ca: ca, cert: cert, key: key},
			},
			wantErr: "invalid Goldmane endpoint",
		},
		{
			name: "cert source failure",
			conf: CalicoScraperConfig{
				Endpoint:   "goldmane.calico-system.svc:7443",
				CertSource: &stubCertSource{err: sourceErr},
			},
			wantErr:   "failed to load TLS credentials for Goldmane",
			wantCalls: 1,
		},
		{
			name: "unparseable material",
			conf: CalicoScraperConfig{
				Endpoint:   "goldmane.calico-system.svc:7443",
				CertSource: &stubCertSource{ca: []byte("not a pem"), cert: cert, key: key},
			},
			wantErr:   "failed to build TLS credentials for Goldmane",
			wantCalls: 1,
		},
		{
			name: "success",
			conf: CalicoScraperConfig{
				Endpoint:   "goldmane.calico-system.svc:7443",
				CertSource: &stubCertSource{ca: ca, cert: cert, key: key},
			},
			wantCalls: 1,
		},
		{
			name: "success with server name override",
			conf: CalicoScraperConfig{
				Endpoint:      "127.0.0.1:7443",
				CertSource:    &stubCertSource{ca: ca, cert: cert, key: key},
				TLSServerName: "goldmane.calico-system.svc",
			},
			wantCalls: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scraper := newTestCalicoScraper(tc.conf)
			conn, err := scraper.newGoldmaneClient(context.Background())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Nil(t, conn)
			} else {
				require.NoError(t, err)
				require.NotNil(t, conn)
				require.NoError(t, conn.Close())
			}
			if source, ok := tc.conf.CertSource.(*stubCertSource); ok {
				assert.Equal(t, tc.wantCalls, source.calls)
			}
		})
	}
}
