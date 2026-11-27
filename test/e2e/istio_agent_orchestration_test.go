package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const istioAgentStatusQuietFor = 12 * time.Second

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

func checkExactViolationCount(ctx context.Context, t *testing.T) {
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
}

// The fixture supplies the disruption and the independent count from the destination.
func checkHandoverTraffic(ctx context.Context, t *testing.T, changeLeader func(), burstPolicyRecords func() int64) {
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

	changeLeader()
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
	burstRecords := burstPolicyRecords()
	require.GreaterOrEqual(t, burstRecords, int64(len(successfulEchoLines(burstResult.stdout))),
		"ztunnel logs must account for every confirmed echo in the burst")
	require.GreaterOrEqual(t, settledCount, countAtDelete+1,
		"settled status must retain the pre-delete count plus a post-handover marker")
	require.GreaterOrEqual(t, settledCount, countAfterSuccessor+1,
		"settled status must retain a post-successor observation")
	require.LessOrEqual(t, settledCount-baseline, burstRecords+1,
		"handover must not count more than the emitted burst records plus the post-handover marker")
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
