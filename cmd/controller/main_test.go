/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/kubewarden/network-enforcer/internal/certsource"
)

// stubManager only implements GetAPIReader for newProviderCertSource tests.
type stubManager struct {
	manager.Manager

	reader client.Reader
}

func (s stubManager) GetAPIReader() client.Reader {
	return s.reader
}

func TestValidateCalicoTLSMode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		tlsMode string
		wantErr string
	}{
		{
			name:    "rejects insecure",
			tlsMode: string(certsource.ModeInsecure),
			wantErr: `calico provider does not support TLS mode "insecure"; use existingSecret or issuer`,
		},
		{
			name:    "allows existingSecret",
			tlsMode: string(certsource.ModeExistingSecret),
		},
		{
			name:    "allows issuer",
			tlsMode: string(certsource.ModeIssuer),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateCalicoTLSMode(tc.tlsMode)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewProviderCertSource(t *testing.T) {
	t.Parallel()

	mgr := stubManager{reader: fake.NewClientBuilder().Build()}

	cases := []struct {
		name    string
		conf    *config
		wantNil bool
		wantErr bool
	}{
		{
			name: "insecure returns nil source",
			conf: &config{
				provider: providerConfig{tlsMode: string(certsource.ModeInsecure)},
			},
			wantNil: true,
		},
		{
			name: "existingSecret API source",
			conf: &config{
				provider: providerConfig{
					tlsMode:        string(certsource.ModeExistingSecret),
					tlsCertSecret:  "calico-system/goldmane-key-pair",
					tlsCAConfigMap: "calico-system/goldmane-ca-bundle",
				},
			},
		},
		{
			name: "existingSecret rejects incomplete flags",
			conf: &config{
				provider: providerConfig{tlsMode: string(certsource.ModeExistingSecret)},
			},
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src, err := newProviderCertSource(mgr, tc.conf)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tc.wantNil {
				require.Nil(t, src)
			} else {
				require.NotNil(t, src)
			}
		})
	}
}

func TestExplicitlySetProviderFlagsIncludesExplicitDefaults(t *testing.T) {
	t.Parallel()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("provider-endpoint", "", "")
	fs.String("provider-tls-mode", "insecure", "")
	fs.String("provider-tls-cert-dir", "", "")
	fs.String("unrelated", "", "")
	require.NoError(t, fs.Parse([]string{"--provider-endpoint=", "--provider-tls-mode=insecure"}))
	require.Equal(t, []string{"provider-endpoint", "provider-tls-mode"}, explicitlySetProviderFlags(fs))
}

func TestNewAgentClientFactory(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		conf    *config
		wantErr bool
	}{
		{
			name: "mTLS disabled returns plaintext factory",
			conf: &config{
				agent: agentConfig{mtlsEnabled: false},
			},
		},
		{
			name: "mTLS enabled rejects a missing cert dir",
			conf: &config{
				agent: agentConfig{mtlsEnabled: true, certDirPath: "/does/not/exist"},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			factory, err := newAgentClientFactory(tc.conf)
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, factory)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, factory)
		})
	}
}
