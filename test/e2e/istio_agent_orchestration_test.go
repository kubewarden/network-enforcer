package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	istioAgentLeaseName      = "6163c1ee.networkenforcer.kubewarden.io"
	istioAgentStatusQuietFor = 12 * time.Second
	istioOrchestrationLimit  = 25 * time.Minute
)

// TestIstioAgentOrchestration exercises the destructive Istio agent/controller
// interactions only on the suite's disposable e2e cluster. Status counts are
// calibrated with attributed, settled warm-up traffic and combined with evidence that
// only the Lease holder starts the puller. Comparing aggregate counts across
// handover does not prove per-event exactly-once delivery.
func TestIstioAgentOrchestration(t *testing.T) {
	suite := loadSuiteConfig()
	if !suite.IsIstioProvider() {
		t.Skip("Skipping Istio agent orchestration test: selected provider is not istio")
	}
	if suite.useExistingCluster {
		t.Skip("Skipping disruptive Istio agent orchestration test on an existing cluster")
	}

	var mesh istioPullFixture
	feature := features.New("Istio agent pull path with three controller replicas").
		Setup(setupTestNamespace).
		Setup(mesh.setup).
		Assess("Only the Lease holder pulls from agents", mesh.onlyLeaderPulls).
		Assess("Violation count equals connections sent", mesh.exactViolationCount).
		Assess("Leader handover does not inflate the violation count", mesh.leaderHandover).
		Assess("The replacement agent is discovered and delivers fresh traffic", mesh.agentReplacement).
		Assess("One pull permit serves both nodes", assessBoundedPermitFairness).
		Assess("The same controller pulls with a renewed CSI client certificate", mesh.clientCertificateRotation).
		Feature()
	testEnv.Test(t, feature)
}

type echoBatchResult struct {
	stdout string
	stderr string
	err    error
}

type orchestrationLeader struct {
	pods    []corev1.Pod
	lease   coordinationv1.Lease
	pod     corev1.Pod
	process managerProcessState
}

func (s *istioPullFixture) onlyLeaderPulls(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	lease := readControllerLease(ctx, t, s.client, s.namespace)
	require.Equal(t, *s.leader.lease.Spec.HolderIdentity, *lease.Spec.HolderIdentity, "initial Lease holder changed")
	requireOnlyLeaseHolderStartedPuller(ctx, t, s.client, s.leader.pods, lease, 1)
	return ctx
}

func (s *istioPullFixture) exactViolationCount(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	const policy = "orchestration-serial-policy"
	warmupUntilAttributed(ctx, t, policy, "orchestration-serial-client", "orchestration-serial-server",
		"orchestration-serial-service", "serial-warmup")
	baseline := waitForSettledViolationCount(ctx, t, policy)

	const measuredConnections = 10
	measuredSuccesses := runFiniteEchoBatch(ctx, t, "orchestration-serial-client", "orchestration-serial-service",
		"serial-measurement", measuredConnections, time.Second, "")
	require.Len(t, measuredSuccesses, measuredConnections,
		"every finite measured TCP connection must echo exactly once")
	waitForExactStableViolationCount(ctx, t, policy, baseline+measuredConnections)
	requireOnlyOrchestrationViolation(ctx, t, policy, "orchestration-serial-client", "orchestration-serial-server")
	s.requireSameLeader(ctx, t)
	return ctx
}

func (s *istioPullFixture) leaderHandover(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	const policy = "orchestration-serial-policy"
	requireNoOrchestrationViolation(ctx, t, policy,
		"orchestration-handover-client", "orchestration-serial-server")
	baseline := getOrchestrationViolationCount(ctx, t, policy)
	progressFile := "/tmp/orchestration-handover-progress"
	const attempts = 75
	interval := 400 * time.Millisecond
	sendCtx, cancelSend := context.WithCancel(ctx)
	resultCh := make(chan echoBatchResult, 1)
	finished := make(chan struct{})
	batchTimeout := finiteEchoDeadline(attempts, interval)
	go func() {
		defer close(finished)
		stdout, stderr, err := execOrchestrationCommand(
			sendCtx,
			"orchestration-handover-client",
			finiteEchoCommand(
				"orchestration-serial-service",
				"handover",
				attempts,
				interval,
				progressFile,
			),
			batchTimeout,
		)
		resultCh <- echoBatchResult{stdout: stdout, stderr: stderr, err: err}
	}()
	t.Cleanup(func() {
		cancelSend()
		select {
		case <-finished:
		case <-time.After(batchTimeout + 5*time.Second):
			t.Error("handover traffic exec did not stop after cancellation or its finite deadline")
		}
	})

	requireHandoverProgress(ctx, t, "orchestration-handover-client", progressFile, 2)
	requireViolationFromSource(ctx, t, policy,
		"orchestration-handover-client", "orchestration-serial-server")
	countAtDelete := getOrchestrationViolationCount(ctx, t, policy)
	require.Greater(t, countAtDelete, baseline, "old Lease holder must process counted traffic before deletion")

	currentLease := readControllerLease(ctx, t, s.client, s.namespace)
	require.Equal(t, *s.leader.lease.Spec.HolderIdentity, *currentLease.Spec.HolderIdentity,
		"the original holder must remain stable until its deletion")
	oldHolder := *currentLease.Spec.HolderIdentity
	oldRenewTime := *currentLease.Spec.RenewTime
	require.NoError(t, s.client.CoreV1().Pods(s.namespace).Delete(ctx, s.leader.pod.Name, metav1.DeleteOptions{}),
		"delete current controller Lease holder")

	successor := s.renewedLeader(ctx, t, oldHolder, &oldRenewTime)
	requireOnlyLeaseHolderStartedPuller(ctx, t, s.client, successor.pods, successor.lease, 1)
	preSuccessorAttempt := latestSuccessfulAttemptID(
		requireHandoverProgressOutput(ctx, t, "orchestration-handover-client", progressFile),
	)
	requireHandoverSuccessAfter(ctx, t, "orchestration-handover-client", progressFile, preSuccessorAttempt)

	countAfterSuccessor := getOrchestrationViolationCount(ctx, t, policy)
	requireNoOrchestrationViolation(ctx, t, policy,
		"orchestration-handover-post-client", "orchestration-serial-server")
	sendEchoOnce(ctx, t, "orchestration-handover-post-client", "orchestration-serial-service", "post-handover-marker")
	requireViolationFromSource(ctx, t, policy,
		"orchestration-handover-post-client", "orchestration-serial-server")
	requireViolationCountIncrease(ctx, t, policy, countAfterSuccessor)

	burstResult := <-resultCh
	require.NoError(t, burstResult.err, "finite handover burst exec")
	require.Empty(t, burstResult.stderr, "finite handover burst stderr")
	require.Len(t, attemptedEchoLines(burstResult.stdout), attempts,
		"finite handover sender must record every bounded one-shot attempt")
	settledCount := waitForSettledViolationCount(ctx, t, policy)
	burstRecords := handoverBurstPolicyRecords(ctx, t, s.client, s.ztunnel)
	require.GreaterOrEqual(t, burstRecords, int64(len(successfulEchoLines(burstResult.stdout))),
		"ztunnel logs must account for every confirmed echo in the burst")
	require.GreaterOrEqual(t, settledCount, countAtDelete+1,
		"settled status must retain the pre-delete count plus a post-handover marker")
	require.GreaterOrEqual(t, settledCount, countAfterSuccessor+1,
		"settled status must retain a post-successor observation")
	require.LessOrEqual(t, settledCount-baseline, burstRecords+1,
		"handover must not count more than the emitted burst records plus the post-handover marker")

	successor.pods = s.readyControllerPods(ctx, t)
	finalLease := readControllerLease(ctx, t, s.client, s.namespace)
	require.Equal(t, *successor.lease.Spec.HolderIdentity, *finalLease.Spec.HolderIdentity,
		"successor must remain Lease holder after the unrelated replacement Pod becomes Ready")
	requireOnlyLeaseHolderStartedPuller(ctx, t, s.client, successor.pods, finalLease, 1)
	s.leader = successor
	return ctx
}

// Count ALLOW-miss records at the destination, independent of the controller.
// A failed echo can still emit a record; an attempt that never reached ztunnel cannot.
func handoverBurstPolicyRecords(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	ztunnel corev1.Pod,
) int64 {
	t.Helper()
	// Only the burst uses this source. Warm-up and the post-handover marker use other pods.
	pods := clientset.CoreV1().Pods(getNamespace(ctx))
	sources, err := pods.List(ctx, metav1.ListOptions{LabelSelector: "app=orchestration-handover-client"})
	require.NoError(t, err)
	require.Len(t, sources.Items, 1)
	sourceIP := sources.Items[0].Status.PodIP
	require.NotEmpty(t, sourceIP)
	servers, err := pods.List(ctx,
		metav1.ListOptions{LabelSelector: "app=orchestration-serial-server"})
	require.NoError(t, err)
	require.Len(t, servers.Items, 1)
	destination := getNamespace(ctx) + "/" + servers.Items[0].Name
	logs, err := readPodLogs(ctx, clientset, ztunnel, "istio-proxy", nil)
	require.NoError(t, err, "read destination ztunnel logs")
	var count int64
	for line := range strings.SplitSeq(logs, "\n") {
		var record struct {
			Message string `json:"message"`
			Proxy   struct {
				Workload string `json:"wl"`
			} `json:"proxy"`
			Inbound struct {
				Peer string `json:"peer"`
			} `json:"inbound"`
		}
		if json.Unmarshal([]byte(line), &record) != nil || record.Message != "dry-run: no allow policies match" ||
			record.Proxy.Workload != destination {
			continue
		}
		if host, _, splitErr := net.SplitHostPort(record.Inbound.Peer); splitErr == nil && host == sourceIP {
			count++
		}
	}
	return count
}

func (s *istioPullFixture) agentReplacement(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	s.requireSameLeader(ctx, t)
	s.replaceWorkerAgent(ctx, t)
	s.requireSameLeader(ctx, t)

	requireNoOrchestrationViolation(ctx, t, "orchestration-serial-policy",
		"orchestration-restart-marker-client", "orchestration-serial-server")
	sendEchoOnce(ctx, t, "orchestration-restart-marker-client",
		"orchestration-serial-service", "restart-post-only-marker")
	requireViolationFromSource(ctx, t, "orchestration-serial-policy",
		"orchestration-restart-marker-client", "orchestration-serial-server")
	return ctx
}

// CSI renews the mounted client credential in place. After all leaves issued
// at baseline expire, replacing the worker agent forces a new TLS connection:
// neither a cached leaf nor an already-authenticated connection can pass.
func (s *istioPullFixture) clientCertificateRotation(
	ctx context.Context,
	t *testing.T,
	_ *envconf.Config,
) context.Context {
	t.Helper()
	s.requireSameLeader(ctx, t)
	baseline := s.requireClientLeafAfter(ctx, t, time.Time{})
	require.LessOrEqual(t, time.Until(baseline), clientLeafLifetime+time.Second, "expected a short-lived CSI leaf")
	t.Logf("Waiting for client leaf on %s to expire at %s", s.leader.pod.Name, baseline.UTC())
	s.requireClientLeafAfter(ctx, t, baseline)
	s.replaceWorkerAgent(ctx, t)
	requireNoOrchestrationViolation(
		ctx,
		t,
		"orchestration-serial-policy",
		"orchestration-cert-marker-client",
		"orchestration-serial-server",
	)
	sendEchoOnce(ctx, t, "orchestration-cert-marker-client", "orchestration-serial-service", "post-renewal-marker")
	requireViolationFromSource(
		ctx,
		t,
		"orchestration-serial-policy",
		"orchestration-cert-marker-client",
		"orchestration-serial-server",
	)
	s.requireSameLeader(ctx, t)
	return ctx
}

func assessBoundedPermitFairness(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	workerCount := waitForSettledViolationCount(ctx, t, "orchestration-serial-policy")
	controlPlaneCount := waitForSettledViolationCount(ctx, t, "orchestration-handover-policy")
	for round := 1; round <= 3; round++ {
		workerTimestamp, workerSeen, err := orchestrationViolationTimestamp(
			ctx, "orchestration-serial-policy", "orchestration-serial-client", "orchestration-serial-server")
		require.NoError(t, err, "read worker tuple timestamp before fairness round %d", round)
		controlTimestamp, controlSeen, err := orchestrationViolationTimestamp(
			ctx, "orchestration-handover-policy", "orchestration-serial-client", "orchestration-handover-server")
		require.NoError(t, err, "read control-plane tuple timestamp before fairness round %d", round)
		if workerSeen {
			waitPastOrchestrationTimestamp(ctx, t, workerTimestamp)
		}
		if controlSeen {
			waitPastOrchestrationTimestamp(ctx, t, controlTimestamp)
		}

		// Send to both nodes before waiting on either agent's status scrape.
		sendEchoOnce(ctx, t, "orchestration-serial-client", "orchestration-serial-service",
			fmt.Sprintf("fairness-worker-round-%d", round))
		sendEchoOnce(ctx, t, "orchestration-serial-client", "orchestration-handover-service",
			fmt.Sprintf("fairness-control-plane-round-%d", round))
		if workerSeen {
			requireViolationTimestampAdvanced(ctx, t, "orchestration-serial-policy",
				"orchestration-serial-client", "orchestration-serial-server", workerTimestamp)
		} else {
			requireViolationFromSource(ctx, t, "orchestration-serial-policy",
				"orchestration-serial-client", "orchestration-serial-server")
		}
		if controlSeen {
			requireViolationTimestampAdvanced(ctx, t, "orchestration-handover-policy",
				"orchestration-serial-client", "orchestration-handover-server", controlTimestamp)
		} else {
			requireViolationFromSource(ctx, t, "orchestration-handover-policy",
				"orchestration-serial-client", "orchestration-handover-server")
		}
		workerCount = requireViolationCountIncrease(ctx, t, "orchestration-serial-policy", workerCount)
		controlPlaneCount = requireViolationCountIncrease(ctx, t, "orchestration-handover-policy", controlPlaneCount)
		t.Logf("max-in-flight=1 fairness round %d advanced both node-local policies with fresh observations", round)
	}
	return ctx
}

func readControllerLease(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace string,
) coordinationv1.Lease {
	t.Helper()
	lease, err := clientset.CoordinationV1().Leases(namespace).Get(ctx, istioAgentLeaseName, metav1.GetOptions{})
	require.NoError(t, err, "read controller Lease")
	require.NotNil(t, lease.Spec.HolderIdentity)
	require.NotNil(t, lease.Spec.RenewTime)
	return *lease
}

func holderPodIndex(pods []corev1.Pod, holder string) (int, bool) {
	for index := range pods {
		if holder == pods[index].Name || strings.HasPrefix(holder, pods[index].Name+"_") {
			return index, true
		}
	}
	return 0, false
}

func findHolderPod(t *testing.T, pods []corev1.Pod, holder string) corev1.Pod {
	t.Helper()
	index, found := holderPodIndex(pods, holder)
	require.True(t, found, "Lease holder %q is not one of the Ready controller pods", holder)
	return pods[index]
}

func requireOnlyLeaseHolderStartedPuller(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	pods []corev1.Pod,
	lease coordinationv1.Lease,
	maxInFlight int,
) {
	t.Helper()
	leader := findHolderPod(t, pods, *lease.Spec.HolderIdentity)
	for _, pod := range pods {
		logs, err := readPodLogs(ctx, clientset, pod, "manager", nil)
		require.NoError(t, err, "read manager logs for controller pod %q", pod.Name)
		const pullerStarted = "Watching Pods for Istio agents"
		if pod.UID == leader.UID {
			require.Contains(t, pod.Spec.Containers[0].Args, fmt.Sprintf("--agent-max-in-flight=%d", maxInFlight),
				"Lease holder Pod must carry the configured maxInFlight flag")
			require.True(t, hasStructuredLogRecord(logs, func(entry map[string]any) bool {
				return entry["msg"] == pullerStarted && entry["maxInFlight"] == float64(maxInFlight)
			}), "Lease holder %q did not start the Istio puller with maxInFlight=%d", pod.Name, maxInFlight)
		} else {
			require.False(t, hasStructuredLogRecord(logs, func(entry map[string]any) bool {
				return entry["msg"] == pullerStarted
			}), "non-holder controller %q started the Istio puller", pod.Name)
		}
	}
}

func readPodLogs(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	pod corev1.Pod,
	container string,
	since *metav1.Time,
) (string, error) {
	options := &corev1.PodLogOptions{Container: container}
	if since != nil {
		options.SinceTime = since
	}
	data, err := clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, options).Do(ctx).Raw()
	return string(data), err
}

type managerProcessState struct {
	containerID  string
	restartCount int32
	startedAt    metav1.Time
}

func requireManagerProcess(t *testing.T, pod corev1.Pod) managerProcessState {
	t.Helper()
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "manager" {
			require.NotEmpty(t, status.ContainerID, "manager container ID")
			require.NotNil(t, status.State.Running, "manager container is running")
			return managerProcessState{
				containerID:  status.ContainerID,
				restartCount: status.RestartCount,
				startedAt:    status.State.Running.StartedAt,
			}
		}
	}
	t.Fatal("manager container status was missing")
	return managerProcessState{}
}

func (s *istioPullFixture) requireSameLeader(ctx context.Context, t *testing.T) {
	t.Helper()
	leader, before := s.leader.pod, s.leader.process
	current, err := s.client.CoreV1().Pods(s.namespace).Get(ctx, leader.Name, metav1.GetOptions{})
	require.NoError(t, err, "read controller leader Pod after operation")
	require.Equal(t, leader.UID, current.UID, "controller leader Pod UID changed")
	state := requireManagerProcess(t, *current)
	require.Equal(t, before.containerID, state.containerID, "controller manager container changed")
	require.Equal(t, before.restartCount, state.restartCount, "controller manager restarted")
	require.Equal(t, before.startedAt, state.startedAt, "controller manager start time changed")
	s.readyControllerPods(ctx, t)
	lease := readControllerLease(ctx, t, s.client, s.namespace)
	require.Equal(t, *s.leader.lease.Spec.HolderIdentity, *lease.Spec.HolderIdentity, "controller Lease holder changed")
}

func requireHandoverProgress(
	ctx context.Context,
	t *testing.T,
	clientDeployment, progressFile string,
	minimum int,
) {
	t.Helper()
	err := wait.For(func(ctx context.Context) (bool, error) {
		stdout, _, err := execInDeploymentRaw(
			ctx,
			clientDeployment,
			[]string{"sh", "-c", "cat " + progressFile + " 2>/dev/null || true"},
		)
		return len(successfulEchoLines(stdout)) >= minimum, err
	}, wait.WithContext(ctx), wait.WithTimeout(20*time.Second), wait.WithInterval(300*time.Millisecond))
	require.NoError(t, err, "handover burst did not reach %d successful sends", minimum)
}

func requireHandoverProgressOutput(ctx context.Context, t *testing.T, clientDeployment, progressFile string) string {
	t.Helper()
	stdout, stderr, err := execInDeploymentRaw(ctx, clientDeployment,
		[]string{"sh", "-c", "cat " + progressFile + " 2>/dev/null || true"})
	require.NoError(t, err, "read finite handover progress")
	require.Empty(t, stderr, "read handover progress stderr")
	return stdout
}

func latestSuccessfulAttemptID(progress string) int {
	latest := -1
	for _, line := range successfulEchoLines(progress) {
		id, err := strconv.Atoi(strings.TrimPrefix(line, "SENT:"))
		if err == nil && id > latest {
			latest = id
		}
	}
	return latest
}

func requireHandoverSuccessAfter(
	ctx context.Context,
	t *testing.T,
	clientDeployment, progressFile string,
	previousID int,
) {
	t.Helper()
	err := wait.For(func(ctx context.Context) (bool, error) {
		stdout, _, err := execInDeploymentRaw(ctx, clientDeployment,
			[]string{"sh", "-c", "cat " + progressFile + " 2>/dev/null || true"})
		return latestSuccessfulAttemptID(stdout) > previousID, err
	}, wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout), wait.WithInterval(500*time.Millisecond))
	require.NoError(t, err, "finite handover sender did not produce a successful attempt above %d", previousID)
}

func finiteEchoCommand(service, prefix string, attempts int, interval time.Duration, progressFile string) []string {
	script := fmt.Sprintf(
		"set -eu\n: > %s\ni=0\nwhile [ \"$i\" -lt %d ]; do\n payload=%s-\"$i\"\n printf 'ATTEMPT:%%s\\n' \"$i\" | tee -a %s\n out=$(printf '%%s' \"$payload\" | nc -w 1 %s 18080 2>/dev/null || true)\n case \"$out\" in *\"$payload\"*) printf 'SENT:%%s\\n' \"$i\" | tee -a %s;; esac\n i=$((i+1))\n if [ \"$i\" -lt %d ]; then sleep %s; fi\ndone",
		progressFile,
		attempts,
		strconv.Quote(prefix),
		progressFile,
		service,
		progressFile,
		attempts,
		strconv.FormatFloat(interval.Seconds(), 'f', 3, 64),
	)
	return []string{"sh", "-c", script}
}

func successfulEchoLines(output string) []string {
	return echoLinesWithPrefix(output, "SENT:")
}

func attemptedEchoLines(output string) []string {
	return echoLinesWithPrefix(output, "ATTEMPT:")
}

func echoLinesWithPrefix(output, prefix string) []string {
	var matching []string
	for line := range strings.SplitSeq(output, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(line, prefix)); err == nil {
			matching = append(matching, line)
		}
	}
	return matching
}

func finiteEchoDeadline(attempts int, interval time.Duration) time.Duration {
	return time.Duration(attempts)*time.Second + time.Duration(attempts-1)*interval + 15*time.Second
}

func execOrchestrationCommand(
	ctx context.Context,
	deployment string,
	command []string,
	deadline time.Duration,
) (string, string, error) {
	var stdout, stderr bytes.Buffer
	execCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	err := getSecurityV1Alpha1Client(ctx).ExecInDeployment(
		execCtx, getNamespace(ctx), deployment, command, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func runFiniteEchoBatch(
	ctx context.Context,
	t *testing.T,
	clientDeployment, service, prefix string,
	attempts int,
	interval time.Duration,
	progressFile string,
) []string {
	t.Helper()
	if progressFile == "" {
		progressFile = "/tmp/orchestration-" + prefix + "-progress"
	}
	stdout, stderr, err := execOrchestrationCommand(ctx, clientDeployment,
		finiteEchoCommand(service, prefix, attempts, interval, progressFile), finiteEchoDeadline(attempts, interval))
	require.NoError(t, err, "run finite echo-checked connection batch")
	require.Empty(t, stderr, "finite echo batch stderr")
	require.Len(t, attemptedEchoLines(stdout), attempts, "finite echo batch must record every one-shot attempt")
	return successfulEchoLines(stdout)
}

func trySendEcho(ctx context.Context, clientDeployment, service, payload string) error {
	command := []string{"sh", "-c", fmt.Sprintf("printf %%s %s | nc -w 2 %s 18080", strconv.Quote(payload), service)}
	stdout, stderr, err := execInDeploymentRaw(ctx, clientDeployment, command)
	if err != nil {
		return err
	}
	if stderr != "" {
		return fmt.Errorf("TCP echo client wrote stderr: %s", stderr)
	}
	if !strings.Contains(stdout, payload) {
		return fmt.Errorf("TCP connection to %q did not echo %q: %q", service, payload, stdout)
	}
	return nil
}

func sendEchoOnce(ctx context.Context, t *testing.T, clientDeployment, service, payload string) {
	t.Helper()
	require.NoError(t, trySendEcho(ctx, clientDeployment, service, payload),
		"send one TCP connection from %q to %q", clientDeployment, service)
}

func readOrchestrationPolicy(ctx context.Context, name string) (v1alpha1.WorkloadNetworkPolicy, error) {
	var policy v1alpha1.WorkloadNetworkPolicy
	err := getSecurityV1Alpha1Client(ctx).Get(ctx, name, getNamespace(ctx), &policy)
	return policy, err
}

func getOrchestrationViolationCount(ctx context.Context, t *testing.T, name string) int64 {
	t.Helper()
	policy, err := readOrchestrationPolicy(ctx, name)
	require.NoError(t, err, "read WorkloadNetworkPolicy %q status", name)
	return policy.Status.ViolationCount
}

func waitForExactStableViolationCount(ctx context.Context, t *testing.T, name string, expected int64) {
	t.Helper()
	err := wait.For(func(ctx context.Context) (bool, error) {
		policy, err := readOrchestrationPolicy(ctx, name)
		return policy.Status.ViolationCount == expected, err
	}, wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout), wait.WithInterval(time.Second))
	require.NoError(t, err, "WorkloadNetworkPolicy %q did not reach exact violationCount=%d", name, expected)
	require.Equal(t, expected, waitForSettledViolationCount(ctx, t, name),
		"WorkloadNetworkPolicy %q violationCount changed during the scrape/status quiet window", name)
}

func waitForSettledViolationCount(ctx context.Context, t *testing.T, name string) int64 {
	t.Helper()
	var stableCount int64
	var unchangedSince time.Time
	err := wait.For(func(ctx context.Context) (bool, error) {
		policy, err := readOrchestrationPolicy(ctx, name)
		if err != nil {
			return false, err
		}
		if unchangedSince.IsZero() || policy.Status.ViolationCount != stableCount {
			stableCount = policy.Status.ViolationCount
			unchangedSince = time.Now()
		}
		return time.Since(unchangedSince) >= istioAgentStatusQuietFor, nil
	}, wait.WithContext(ctx), wait.WithTimeout(2*defaultOperationTimeout), wait.WithInterval(time.Second))
	require.NoError(t, err, "WorkloadNetworkPolicy %q violationCount did not settle", name)
	return stableCount
}

// Only unmeasured warm-up traffic is retried. Give each echo a scrape/status
// window before sending another; all reads and execs share the overall timeout.
func warmupUntilAttributed(
	ctx context.Context,
	t *testing.T,
	policyName, sourceName, destinationName, service, payload string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, defaultOperationTimeout)
	defer cancel()
	requireNoOrchestrationViolation(ctx, t, policyName, sourceName, destinationName)
	err := wait.For(func(ctx context.Context) (bool, error) {
		if err := trySendEcho(ctx, sourceName, service, payload); err != nil {
			t.Logf("warm-up echo: %v", err)
			return false, nil
		}
		err := wait.For(violationFromSource(policyName, sourceName, destinationName), wait.WithContext(ctx),
			wait.WithTimeout(30*time.Second), wait.WithInterval(500*time.Millisecond), wait.WithImmediate())
		if errors.Is(err, context.DeadlineExceeded) {
			return false, ctx.Err()
		}
		return err == nil, err
	}, wait.WithContext(ctx), wait.WithImmediate(), wait.WithInterval(time.Second))
	require.NoError(t, err, "wait for warm-up violation on %s from %s", policyName, sourceName)
}

func requireOnlyOrchestrationViolation(
	ctx context.Context,
	t *testing.T,
	policyName, sourceName, destinationName string,
) {
	t.Helper()
	policy, err := readOrchestrationPolicy(ctx, policyName)
	require.NoError(t, err, "read WorkloadNetworkPolicy %q attribution", policyName)
	require.Len(t, policy.Status.Violations, 1, "policy must contain only the measured flow")
	require.True(t, isExpectedOrchestrationViolation(&policy.Status.Violations[0],
		getNamespace(ctx), policyName, sourceName, destinationName),
		"policy contains an unexpected source, destination, protocol, action, or policy attribution: %+v",
		policy.Status.Violations[0])
}

func findExpectedOrchestrationViolation(
	violations []v1alpha1.ViolationRecord,
	namespace, policyName, sourceName, destinationName string,
) *v1alpha1.ViolationRecord {
	for index := range violations {
		if isExpectedOrchestrationViolation(&violations[index], namespace, policyName, sourceName, destinationName) {
			return &violations[index]
		}
	}
	return nil
}

func isExpectedOrchestrationViolation(
	violation *v1alpha1.ViolationRecord,
	namespace, policyName, sourceName, destinationName string,
) bool {
	return violation.Source.Namespace == namespace && violation.Source.OwnerKind == v1alpha1.WorkloadKindDeployment &&
		violation.Source.OwnerName == sourceName && violation.Dest.Namespace == namespace &&
		violation.Dest.OwnerKind == v1alpha1.WorkloadKindDeployment && violation.Dest.OwnerName == destinationName &&
		violation.Protocol == corev1.ProtocolTCP &&
		violation.Action == v1alpha1.WorkloadNetworkPolicyModeMonitor &&
		violation.DenyingPolicyNamespace == namespace && violation.DenyingPolicyName == policyName
}

func requireNoOrchestrationViolation(
	ctx context.Context,
	t *testing.T,
	policyName, sourceName, destinationName string,
) {
	t.Helper()
	policy, err := readOrchestrationPolicy(ctx, policyName)
	require.NoError(t, err, "read WorkloadNetworkPolicy %q before fresh traffic", policyName)
	require.Nil(t, findExpectedOrchestrationViolation(
		policy.Status.Violations, getNamespace(ctx), policyName, sourceName, destinationName),
		"source/destination tuple must be absent before its fresh marker")
}

func requireViolationFromSource(
	ctx context.Context,
	t *testing.T,
	policyName, sourceName, destinationName string,
) {
	t.Helper()
	err := wait.For(violationFromSource(policyName, sourceName, destinationName), wait.WithContext(ctx),
		wait.WithTimeout(defaultOperationTimeout), wait.WithInterval(time.Second))
	require.NoError(
		t,
		err,
		"WorkloadNetworkPolicy %q did not contain source %q to destination %q",
		policyName,
		sourceName,
		destinationName,
	)
}

func violationFromSource(policyName, sourceName, destinationName string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		policy, err := readOrchestrationPolicy(ctx, policyName)
		return findExpectedOrchestrationViolation(
			policy.Status.Violations,
			getNamespace(ctx),
			policyName,
			sourceName,
			destinationName,
		) != nil, err
	}
}

func orchestrationViolationTimestamp(
	ctx context.Context,
	policyName, sourceName, destinationName string,
) (metav1.Time, bool, error) {
	policy, err := readOrchestrationPolicy(ctx, policyName)
	if err != nil {
		return metav1.Time{}, false, err
	}
	violation := findExpectedOrchestrationViolation(
		policy.Status.Violations, getNamespace(ctx), policyName, sourceName, destinationName)
	if violation == nil {
		return metav1.Time{}, false, nil
	}
	return violation.Timestamp, true, nil
}

func waitPastOrchestrationTimestamp(ctx context.Context, t *testing.T, previous metav1.Time) {
	t.Helper()
	// Status timestamps are serialized at second precision; let the source
	// clock move beyond the previous server-reported second before sending.
	wait := time.Until(previous.Time.Add(1100 * time.Millisecond))
	if wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatalf("context ended while separating status timestamp seconds: %v", ctx.Err())
	case <-timer.C:
	}
}

func requireViolationTimestampAdvanced(
	ctx context.Context,
	t *testing.T,
	policyName, sourceName, destinationName string,
	previous metav1.Time,
) {
	t.Helper()
	err := wait.For(func(ctx context.Context) (bool, error) {
		current, found, err := orchestrationViolationTimestamp(ctx, policyName, sourceName, destinationName)
		return found && current.After(previous.Time), err
	}, wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout), wait.WithInterval(time.Second))
	require.NoError(t, err, "WorkloadNetworkPolicy %q did not advance timestamp for %s to %s beyond %s",
		policyName, sourceName, destinationName, previous.Time.UTC().Format(time.RFC3339))
}

func requireViolationCountIncrease(ctx context.Context, t *testing.T, name string, previous int64) int64 {
	t.Helper()
	var current int64
	err := wait.For(func(ctx context.Context) (bool, error) {
		policy, err := readOrchestrationPolicy(ctx, name)
		current = policy.Status.ViolationCount
		return current > previous, err
	}, wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout), wait.WithInterval(time.Second))
	require.NoError(t, err, "WorkloadNetworkPolicy %q made no progress beyond count %d", name, previous)
	return current
}

func hasStructuredLogRecord(logs string, matches func(map[string]any) bool) bool {
	for line := range strings.SplitSeq(logs, "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) == nil && matches(entry) {
			return true
		}
	}
	return false
}
