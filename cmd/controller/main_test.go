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
	"os"
	"path/filepath"
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

func TestResolveAgentNamespace(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		override   string
		contents   string
		createFile bool
		want       string
		wantErr    string
	}{
		{name: "service account", contents: "controller-system\n", createFile: true, want: "controller-system"},
		{name: "explicit override without service account", override: "local-agents", want: "local-agents"},
		{
			name:       "explicit override wins",
			override:   "other-agents",
			contents:   "controller-system",
			createFile: true,
			want:       "other-agents",
		},
		{name: "missing service account", wantErr: "set --agent-namespace outside a Pod"},
		{name: "empty service account namespace", contents: "\n", createFile: true, wantErr: "namespace is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "namespace")
			if tc.createFile {
				require.NoError(t, os.WriteFile(path, []byte(tc.contents), 0o600))
			}
			got, err := resolveAgentNamespace(tc.override, path)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
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

func TestAgentTLSFlags(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		args     []string
		wantMTLS bool
	}{
		{name: "enables mTLS by default", wantMTLS: true},
		{name: "allows explicit opt-out", args: []string{"--agent-grpc-mtls-enabled=false"}},
		{name: "allows explicit opt-in", args: []string{"--agent-grpc-mtls-enabled=true"}, wantMTLS: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			var conf agentConfig
			registerAgentTLSFlags(flags, &conf)
			args := append([]string{"--agent-grpc-mtls-cert-dir=/etc/network-enforcer/certs"}, tc.args...)
			require.NoError(t, flags.Parse(args))
			require.Equal(t, tc.wantMTLS, conf.mtlsEnabled)
			require.Equal(t, "/etc/network-enforcer/certs", conf.certDirPath)
		})
	}
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
