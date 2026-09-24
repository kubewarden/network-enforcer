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

func TestIstioTLSCertDir(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		tlsMode    string
		tlsCertDir string
		wantDir    string
		wantErr    string
	}{
		{
			name:       "insecure allows empty cert dir",
			tlsMode:    string(certsource.ModeInsecure),
			tlsCertDir: "",
			wantDir:    "",
		},
		{
			name:       "issuer requires cert dir",
			tlsMode:    string(certsource.ModeIssuer),
			tlsCertDir: "",
			wantErr:    `istio provider TLS mode "issuer" requires --provider-tls-cert-dir`,
		},
		{
			name:       "issuer with cert dir",
			tlsMode:    string(certsource.ModeIssuer),
			tlsCertDir: "/etc/provider/certs",
			wantDir:    "/etc/provider/certs",
		},
		{
			name:       "existingSecret requires cert dir",
			tlsMode:    string(certsource.ModeExistingSecret),
			tlsCertDir: "",
			wantErr:    `istio provider TLS mode "existingSecret" requires --provider-tls-cert-dir`,
		},
		{
			name:       "existingSecret with cert dir",
			tlsMode:    string(certsource.ModeExistingSecret),
			tlsCertDir: "/etc/provider/certs",
			wantDir:    "/etc/provider/certs",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := istioTLSCertDir(tc.tlsMode, tc.tlsCertDir)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantDir, got)
		})
	}
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
