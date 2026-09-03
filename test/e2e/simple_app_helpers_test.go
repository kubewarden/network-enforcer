package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	testFolder                    = "./testdata"
	simpleAppManifest             = "simple_app.yaml"
	simpleAppClientDeploymentName = "http-client"
	simpleAppServerDeploymentName = "http-server"
	simpleAppClientServiceAccount = "http-client-sa"
	simpleAppTCPServicePort       = int32(18080)
	simpleAppUDPServicePort       = int32(18083)
	simpleAppUDPServerPort        = int32(18081)
	// simpleAppViolatingServicePort is a service port the server echoes on but
	// that is NOT part of any learned policy: traffic to it is a violation
	// (observed in monitor mode, blocked in protect mode) while still echoing
	// the payload so tests can rely on the round-trip.
	simpleAppViolatingServicePort = int32(18082)
)

func teardownSimpleAppWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	namespace := getNamespace(ctx)

	err := decoder.DeleteWithManifestDir(
		ctx,
		getSecurityV1Alpha1Client(ctx),
		testFolder,
		simpleAppManifest,
		[]resources.DeleteOption{},
		decoder.MutateNamespace(namespace),
	)
	require.NoError(t, err, "failed to delete simple app manifest")

	clientDeployment := &appsv1.Deployment{
		Name: simpleAppClientDeploymentName, Namespace: namespace,
	}
	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).ResourceDeleted(clientDeployment),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait client deployment deletion")

	serverDeployment := &appsv1.Deployment{
		Name: simpleAppServerDeploymentName, Namespace: namespace,
	}
	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).ResourceDeleted(serverDeployment),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait server deployment deletion")

	return ctx
}

func setupSimpleAppWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	t.Log("installing simple app")
	namespace := getNamespace(ctx)

	err := decoder.ApplyWithManifestDir(
		ctx,
		getSecurityV1Alpha1Client(ctx),
		testFolder,
		simpleAppManifest,
		[]resources.CreateOption{},
		// we should mutate the nodeSelector here, since we want them both on the same node and on different nodes.
		decoder.MutateNamespace(namespace),
	)
	require.NoError(t, err, "failed to apply simple app manifest")

	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).DeploymentAvailable(simpleAppClientDeploymentName, namespace),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait client deployment ready")

	err = wait.For(
		conditions.New(getSecurityV1Alpha1Client(ctx)).DeploymentAvailable(simpleAppServerDeploymentName, namespace),
		wait.WithTimeout(defaultOperationTimeout),
	)
	require.NoError(t, err, "wait server deployment ready")
	return ctx
}

func getProtoCmd(proto corev1.Protocol, port int32) (string, []string) {
	const (
		tcpPayload           = "tcp-e2e-payload"
		udpPayload           = "udp-e2e-payload"
		simpleAppServiceName = "http-service"
	)

	switch proto {
	case corev1.ProtocolTCP:
		return tcpPayload, []string{
			"sh",
			"-c",
			fmt.Sprintf(
				"printf %s | nc -w 2 %s %d",
				strconv.Quote(tcpPayload),
				simpleAppServiceName,
				port,
			),
		}
	case corev1.ProtocolUDP:
		// UDP is out of scope for the Istio ambient path (traffic does not
		// pass through ztunnel), but it will be needed for the calico and
		// cilium providers.
		return udpPayload, []string{
			"sh",
			"-c",
			fmt.Sprintf(
				"printf %s | nc -u -w 2 %s %d",
				strconv.Quote(udpPayload),
				simpleAppServiceName,
				port,
			),
		}
	case corev1.ProtocolSCTP:
		fallthrough
	default:
		panic(fmt.Sprintf("unsupported protocol: %v", proto))
	}
}

// execInSimpleClientDeploymentRaw executes a command in the client deployment's
// first pod without asserting on the error, so callers can distinguish allowed
// (no error, echoed payload) from blocked (rejected connection) traffic.
func execInSimpleClientDeploymentRaw(
	ctx context.Context,
	command []string,
) (string, string, error) {
	namespace := getNamespace(ctx)
	r := getSecurityV1Alpha1Client(ctx)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	execCtx, cancel := context.WithTimeout(ctx, defaultPodExecTimeout)
	defer cancel()

	err := r.ExecInDeployment(
		execCtx,
		namespace,
		simpleAppClientDeploymentName,
		command,
		&stdout,
		&stderr,
	)
	return stdout.String(), stderr.String(), err
}

// assertPacketSentFromClient sends a payload to the simple app service on the
// given port and asserts the echo comes back (traffic allowed).
func assertPacketSentFromClient(
	ctx context.Context,
	t *testing.T,
	proto corev1.Protocol,
	port int32,
) context.Context {
	t.Helper()

	payload, cmd := getProtoCmd(proto, port)
	stdout, stderr, err := execInSimpleClientDeploymentRaw(ctx, cmd)
	require.NoError(t, err, "failed executing command in deployment %q: %v", simpleAppClientDeploymentName, err)
	require.Empty(t, stderr)
	require.Contains(t, stdout, payload, "client output should contain echoed payload")
	return ctx
}

// assertPacketBlockedFromClient sends a payload to the simple app service on
// the given port and asserts the echo never comes back (traffic blocked). The
// client-side nc may still exit 0 when the data plane rejects the connection:
// the reliable signal is the missing echo, so we keep retrying until the
// payload stops being echoed.
func assertPacketBlockedFromClient(
	ctx context.Context,
	t *testing.T,
	proto corev1.Protocol,
	port int32,
) context.Context {
	t.Helper()

	payload, cmd := getProtoCmd(proto, port)
	require.Eventually(t, func() bool {
		// we need to try multiple times because it may take some time for the policy to be enforced.
		stdout, _, _ := execInSimpleClientDeploymentRaw(ctx, cmd)
		if strings.Contains(stdout, payload) {
			t.Logf("traffic to port %d still echoing", port)
			return false
		}
		return true
	}, defaultOperationTimeout, 1*time.Second,
		"traffic to port %d should be blocked: payload %q should not be echoed", port, payload)
	return ctx
}
