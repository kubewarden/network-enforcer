package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/network-enforcer/internal/tailer"
)

func TestParseAgentArgs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		args       []string
		want       agentOptions
		wantErr    error
		wantErrMsg string
	}{
		{
			name: "uses the production matcher and mTLS by default",
			want: agentOptions{
				logGlob:        defaultLogGlob,
				pollInterval:   defaultPollInterval,
				grpcPort:       defaultGRPCPort,
				grpcTLSEnabled: true,
			},
		},
		{
			name:    "handles help without treating it as invalid input",
			args:    []string{"--help"},
			wantErr: flag.ErrHelp,
		},
		{
			name: "accepts tuning and explicit mTLS opt-out",
			args: []string{
				"--poll-interval", "1s",
				"--log-glob=/tmp/forbidden/*.log",
				"--grpc-port", "40123",
				"--grpc-mtls-enabled=false",
				"--grpc-expected-client-san=",
			},
			want: agentOptions{
				logGlob:      "/tmp/forbidden/*.log",
				pollInterval: time.Second,
				grpcPort:     40123,
			},
		},
		{
			name:       "rejects positional arguments",
			args:       []string{"unexpected"},
			wantErrMsg: "unexpected positional arguments",
		},
		{
			name:       "rejects arguments after the flag terminator",
			args:       []string{"--", "--grpc-mtls-enabled=false"},
			wantErrMsg: "unexpected positional arguments",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			options, err := parseAgentArgs(tc.args)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			if tc.wantErrMsg != "" {
				require.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, options)
		})
	}
}

func TestParseAgentArgsWithChartPins(t *testing.T) {
	t.Parallel()

	chartArgs := []string{
		"--log-glob=" + defaultLogGlob,
		"--grpc-port=50123",
		"--grpc-mtls-cert-dir=/etc/network-enforcer/certs",
		"--grpc-expected-client-san=network-enforcer-controller",
	}
	cases := []struct {
		name           string
		userArgs       []string
		wantMTLS       bool
		wantPollPeriod time.Duration
		wantErr        string
	}{
		{
			name:     "rejects a dangling client SAN flag",
			userArgs: []string{"--log-glob=/var/log/pods/*/*/*.log", "--grpc-expected-client-san"},
			wantErr:  "must use an equals value",
		},
		{
			name:     "rejects a dangling certificate directory flag",
			userArgs: []string{"--log-glob=/var/log/pods/*/*/*.log", "--grpc-mtls-cert-dir"},
			wantErr:  "must use an equals value",
		},
		{
			name: "retains chart-owned settings after tuning arguments",
			userArgs: []string{
				"--poll-interval", "1s",
				"--log-glob=/tmp/forbidden/*.log",
				"--grpc-port", "40123",
				"--grpc-expected-client-san", "tuning-client",
			},
			wantMTLS:       true,
			wantPollPeriod: time.Second,
		},
		{
			name:           "allows explicit mTLS opt-out without a chart override",
			userArgs:       []string{"--grpc-mtls-enabled=false"},
			wantPollPeriod: defaultPollInterval,
		},
		{
			name:     "rejects a flag terminator before chart arguments",
			userArgs: []string{"--"},
			wantErr:  "unexpected positional arguments",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			options, err := parseAgentArgs(append(tc.userArgs, chartArgs...))
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, agentOptions{
				logGlob:               defaultLogGlob,
				pollInterval:          tc.wantPollPeriod,
				grpcPort:              50123,
				grpcTLSEnabled:        tc.wantMTLS,
				grpcCertDir:           "/etc/network-enforcer/certs",
				grpcExpectedClientSAN: "network-enforcer-controller",
			}, options)
		})
	}
}

func TestProductionLogPatternExcludesUntrustedPaths(t *testing.T) {
	nodeLogRoot := t.TempDir()
	podsDir := filepath.Join(nodeLogRoot, "pods")
	containersDir := filepath.Join(nodeLogRoot, "containers")
	ztunnelLog := filepath.Join(
		podsDir,
		"istio-system_ztunnel-945js_30c12516-0105-4c0a-ab4f-d2f734a4343a",
		"ztunnel",
		"0.log",
	)
	proxyLog := filepath.Join(
		podsDir,
		"istio-system_ztunnel-ldcxt_54f9e53e-c978-4cd2-a268-883ad37aee2d",
		"istio-proxy",
		"0.log",
	)
	paths := []string{
		ztunnelLog,
		proxyLog,
		filepath.Join(podsDir, "tenant_ztunnel-pod_30c12516-0105-4c0a-ab4f-d2f734a4343a", "ztunnel", "0.log"),
		filepath.Join(
			podsDir,
			"istio-system_ztunnelish-945js_30c12516-0105-4c0a-ab4f-d2f734a4343a",
			"istio-proxy",
			"0.log",
		),
		filepath.Join(
			podsDir,
			"istio-system_ztunnel-sidecar_30c12516-0105-4c0a-ab4f-d2f734a4343a",
			"istio-cni",
			"0.log",
		),
		filepath.Join(
			podsDir,
			"istio-system_ztunnel-945js_30c12516-0105-4c0a-ab4f-d2f734a4343a",
			"ztunnel",
			"0.log.gz",
		),
		filepath.Join(
			podsDir,
			"istio-system_ztunnel-945js_30c12516-0105-4c0a-ab4f-d2f734a4343a",
			"ztunnel",
			"0.log.tmp",
		),
		filepath.Join(
			podsDir,
			"istio-system_ztunnel-945js_30c12516-0105-4c0a-ab4f-d2f734a4343a",
			"ztunnel",
			"0.log.20261029",
		),
	}
	for _, path := range paths {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, nil, 0o600))
	}
	require.NoError(t, os.MkdirAll(containersDir, 0o700))
	require.NoError(
		t,
		os.Symlink(ztunnelLog, filepath.Join(containersDir, "ztunnel-945js_istio-system_ztunnel-abcdef123456.log")),
	)

	glob := filepath.Join(podsDir, strings.TrimPrefix(defaultLogGlob, "/var/log/pods/"))
	observed := make(chan []string, 1)
	fileTailer, err := tailer.New(tailer.Config{
		Include:      []string{glob},
		PollInterval: 20 * time.Millisecond,
		OnFilesObserved: func(files []string) {
			select {
			case observed <- files:
			default:
			}
		},
	}, func(tailer.Line) {})
	require.NoError(t, err)
	require.NoError(t, fileTailer.Start())
	t.Cleanup(func() { require.NoError(t, fileTailer.Stop()) })

	select {
	case files := <-observed:
		assert.ElementsMatch(t, []string{ztunnelLog, proxyLog}, files)
	case <-time.After(time.Second):
		t.Fatal("tailer did not report matching files")
	}
}

func TestRunDrainsPreRenameLogAndReadsReplacementWithProductionPattern(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(
		root,
		"istio-system_ztunnel-ldcxt_54f9e53e-c978-4cd2-a268-883ad37aee2d",
		"istio-proxy",
		"0.log",
	)
	require.NoError(t, os.MkdirAll(filepath.Dir(active), 0o700))
	require.NoError(t, os.WriteFile(active, nil, 0o600))
	glob := filepath.Join(root, strings.TrimPrefix(defaultLogGlob, "/var/log/pods/"))

	lineEvents := make(chan string, 16)
	observed := make(chan []string, 16)
	cfg := tailer.Config{
		Include:      []string{glob},
		PollInterval: defaultPollInterval,
		StartAt:      "beginning",
		OnFilesObserved: func(files []string) {
			select {
			case observed <- files:
			default:
			}
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- run(ctx, cfg, func(line tailer.Line) {
			lineEvents <- string(line.Raw)
		}, logger, waitForCancellation)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("run did not stop after the context was canceled")
		}
	})

	waitForObservedPath(t, observed, active, 1)
	appendTestLogLine(t, active, "active-file")
	got := receiveTestLines(t, lineEvents, 1)
	drainObservedFiles(observed)
	waitForObservedPath(t, observed, active, 2)

	appendTestLogLine(t, active, "unread-before-rename")
	rotated := active + ".20261029"
	require.NoError(t, os.Rename(active, rotated))
	require.NoError(t, os.WriteFile(active, []byte("replacement-file\n"), 0o600))
	got = append(got, receiveTestLines(t, lineEvents, 2)...)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after the context was canceled")
	}
	assert.ElementsMatch(t, []string{"active-file", "unread-before-rename", "replacement-file"}, got)
}

func appendTestLogLine(t *testing.T, path, line string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = fmt.Fprintln(file, line)
	require.NoError(t, err)
	require.NoError(t, file.Close())
}

func receiveTestLines(t *testing.T, lines <-chan string, count int) []string {
	t.Helper()
	got := make([]string, 0, count)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for len(got) < count {
		select {
		case line := <-lines:
			got = append(got, line)
		case <-timer.C:
			t.Fatalf("timed out waiting for %d log lines", count)
		}
	}
	return got
}

func waitForObservedPath(t *testing.T, observed <-chan []string, path string, count int) {
	t.Helper()
	matches := 0
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for matches < count {
		select {
		case files := <-observed:
			if slices.Contains(files, path) {
				matches++
			}
		case <-timer.C:
			t.Fatalf("timed out waiting to observe %s", path)
		}
	}
}

func drainObservedFiles(observed <-chan []string) {
	for {
		select {
		case <-observed:
		default:
			return
		}
	}
}

func TestRunTailsAndStops(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "0.log")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))

	var mu sync.Mutex
	var got []string
	h := func(l tailer.Line) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, string(l.Raw))
	}

	cfg := tailer.Config{
		Include:      []string{filepath.Join(dir, "*.log*")},
		PollInterval: 20 * time.Millisecond,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, h, logger, waitForCancellation) }()

	time.Sleep(100 * time.Millisecond)
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = fmt.Fprintln(f, "2026-10-29T13:00:00.000000001Z stdout F hello")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 1
	}, 3*time.Second, 20*time.Millisecond)

	cancel()
	select {
	case errRun := <-done:
		require.NoError(t, errRun)
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after the context was canceled")
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"2026-10-29T13:00:00.000000001Z stdout F hello"}, got)
}
