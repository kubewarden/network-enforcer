package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"istio.io/api/annotation"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	istioAgentLeaseName      = "6163c1ee.networkenforcer.kubewarden.io"
	istioAgentStatusQuietFor = 12 * time.Second
	istioOrchestrationLimit  = 25 * time.Minute
	istioAgentControllerCert = "agent-orchestration-controller-certs"
	istioAgentServerCert     = "agent-orchestration-server-certs"
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
		Assess("Client certificate rotation recovers without a controller restart", mesh.clientCertificateRotation).
		Feature()
	testEnv.Test(t, feature)
}

// Per-feature state. Handover and replacement update the leader and worker agent;
// setup supplies both even when individual assessments are selected by name.
type istioPullFixture struct {
	client                         *kubernetes.Clientset
	namespace, controller, agentDS string
	ztunnel, workerAgent           corev1.Pod
	leader                         orchestrationLeader
	certificates                   orchestrationCertificateSet
}

func (s *istioPullFixture) setup(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, istioOrchestrationLimit)
	t.Cleanup(cancel)
	// WithFailFast skips feature teardown. Register cleanup before setup can
	// fail; shared workload rollback runs first (Cleanup is LIFO).
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), defaultOperationTimeout)
		defer stop()
		teardownTestNamespace(cleanupCtx, t, cfg)
	})
	ctx = labelNamespaceAmbient(ctx, t, cfg)

	clientset, clientErr := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	require.NoError(t, clientErr, "create Kubernetes client for orchestration test")
	suite := getSuiteConfig(ctx)
	releaseNamespace := suite.releaseNS
	controllerName := suite.releaseName + "-controller-manager"
	agentName := suite.releaseName + "-agent"

	originalController := &appsv1.Deployment{}
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Get(ctx, controllerName, releaseNamespace, originalController),
		"get controller Deployment before orchestration changes")
	originalAgent := &appsv1.DaemonSet{}
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Get(ctx, agentName, releaseNamespace, originalAgent),
		"get agent DaemonSet before orchestration changes")
	s.client, s.namespace, s.controller, s.agentDS = clientset, releaseNamespace, controllerName, agentName
	createdSecrets := make(map[string]types.UID)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer stop()
		s.restoreWorkloads(cleanupCtx, t, originalController, originalAgent, createdSecrets)
	})

	workerNode, controlPlaneNode := requireIstioOrchestrationNodes(ctx, t, clientset)
	s.ztunnel = requireNodeHasReadyDaemonSetPod(ctx, t, clientset, "ztunnel", istioNamespace, workerNode)
	requireNodeHasReadyDaemonSetPod(ctx, t, clientset, "ztunnel", istioNamespace, controlPlaneNode)
	requireNodeHasReadyDaemonSetPod(ctx, t, clientset, agentName, releaseNamespace, workerNode)
	requireNodeHasReadyDaemonSetPod(ctx, t, clientset, agentName, releaseNamespace, controlPlaneNode)

	createOrchestrationWorkloads(ctx, t, workerNode, controlPlaneNode)
	createIstioOrchestrationPolicy(ctx, t, "orchestration-serial-policy", "orchestration-serial-server")
	createIstioOrchestrationPolicy(ctx, t, "orchestration-handover-policy", "orchestration-handover-server")

	certificates := makeOrchestrationCertificates(t, releaseNamespace)
	controllerSecret, err := createOrchestrationSecret(ctx, clientset, releaseNamespace,
		istioAgentControllerCert, certificates.controllerA)
	require.NoError(t, err, "create temporary controller gRPC certificate Secret")
	createdSecrets[istioAgentControllerCert] = controllerSecret
	agentSecret, err := createOrchestrationSecret(ctx, clientset, releaseNamespace,
		istioAgentServerCert, certificates.agentA)
	require.NoError(t, err, "create temporary agent gRPC certificate Secret")
	createdSecrets[istioAgentServerCert] = agentSecret

	configureOrchestrationWorkloads(ctx, t, clientset, releaseNamespace,
		controllerName, agentName, istioAgentControllerCert, istioAgentServerCert)
	agents := requireReadyAgentsOnNodes(ctx, t, clientset, releaseNamespace, agentName,
		[]string{workerNode, controlPlaneNode})
	require.Len(t, agents, 2, "expected one release-owned agent on each Kind node")
	s.workerAgent = findAgentOnNode(t, agents, workerNode)
	s.certificates = certificates
	pods := requireReadyControllerPods(ctx, t, clientset, releaseNamespace, controllerName, 3)
	lease := requireRenewedControllerLease(ctx, t, clientset, releaseNamespace, pods, nil)
	holder := findHolderPod(t, pods, *lease.Spec.HolderIdentity)
	s.leader = orchestrationLeader{pods: pods, lease: lease, pod: holder, process: requireManagerProcess(t, holder)}
	waitForOrchestrationPolicies(ctx, t)
	return ctx
}

func (s *istioPullFixture) restoreWorkloads(ctx context.Context, t *testing.T, controller *appsv1.Deployment,
	agent *appsv1.DaemonSet, secrets map[string]types.UID,
) {
	t.Helper()
	depOK := assert.NoError(t, restoreDeploymentSpec(ctx, s.client, s.namespace, s.controller, &controller.Spec),
		"restore controller Deployment")
	dsOK := assert.NoError(t, restoreDaemonSetSpec(ctx, s.client, s.namespace, s.agentDS, &agent.Spec),
		"restore agent DaemonSet")
	if !depOK || !dsOK {
		return
	}

	// DeploymentAvailable can still be true for the old revision. Wait for
	// the restored pods on both workloads before removing the test Secrets.
	c := conditions.New(getSecurityV1Alpha1Client(ctx))
	expected := ptr.Deref(controller.Spec.Replicas, 1)
	depReady := c.ResourceMatch(controller, func(_ k8s.Object) bool {
		status := controller.Status
		return ptr.Deref(controller.Spec.Replicas, 1) == expected && status.ObservedGeneration >= controller.Generation &&
			status.Replicas == expected &&
			status.UpdatedReplicas == expected &&
			status.ReadyReplicas == expected &&
			status.AvailableReplicas == expected
	})
	dsReady := c.DaemonSetReady(agent)
	depOK = assert.NoError(t, wait.For(depReady, wait.WithContext(ctx)), "wait for restored controller replicas")
	dsOK = assert.NoError(t, wait.For(func(ctx context.Context) (bool, error) {
		ready, err := dsReady(ctx)
		return ready && agent.Status.ObservedGeneration >= agent.Generation, err
	}, wait.WithContext(ctx)), "wait for restored agent DaemonSet")
	if !depOK || !dsOK {
		return
	}
	for name, uid := range secrets {
		if podSpecUsesSecret(&controller.Spec.Template.Spec, name) ||
			podSpecUsesSecret(&agent.Spec.Template.Spec, name) {
			t.Errorf("temporary certificate Secret %q is still referenced by a restored workload", name)
			continue
		}
		err := s.client.CoreV1().Secrets(s.namespace).Delete(ctx, name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		})
		if !apierrors.IsNotFound(err) {
			assert.NoError(t, err, "delete temporary certificate Secret %q", name)
		}
	}
}

func podSpecUsesSecret(spec *corev1.PodSpec, name string) bool {
	for _, volume := range spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName == name {
			return true
		}
	}
	return false
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

	lease, successor, livePods := requireRenewedControllerLeaseOnLivePod(
		ctx, t, s.client, s.namespace, s.controller, oldHolder, &oldRenewTime)
	require.NotEqual(t, oldHolder, *lease.Spec.HolderIdentity, "handover must elect a different controller process")
	requireOnlyLeaseHolderStartedPuller(ctx, t, s.client, livePods, lease, 1)
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

	pods := requireReadyControllerPods(ctx, t, s.client, s.namespace, s.controller, 3)
	finalLease := readControllerLease(ctx, t, s.client, s.namespace)
	require.Equal(t, *lease.Spec.HolderIdentity, *finalLease.Spec.HolderIdentity,
		"successor must remain Lease holder after the unrelated replacement Pod becomes Ready")
	requireOnlyLeaseHolderStartedPuller(ctx, t, s.client, pods, finalLease, 1)
	s.leader = orchestrationLeader{
		pods:    pods,
		lease:   finalLease,
		pod:     successor,
		process: requireManagerProcess(t, successor),
	}
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
	old := s.workerAgent
	require.NoError(t, s.client.CoreV1().Pods(s.namespace).Delete(ctx, old.Name, metav1.DeleteOptions{}),
		"delete destination-node agent Pod")
	s.workerAgent = requireReplacementAgent(ctx, t, s.client, s.namespace, s.agentDS, old.Spec.NodeName, old.UID)
	requireEventuallyAgentTailerStarted(ctx, t, s.client, s.namespace, s.workerAgent)
	s.requireSameLeader(ctx, t)
	requireLeaderDiscoveredAgentUID(ctx, t, s.client, s.leader.pod, s.workerAgent)

	requireNoOrchestrationViolation(ctx, t, "orchestration-serial-policy",
		"orchestration-restart-marker-client", "orchestration-serial-server")
	sendEchoOnce(ctx, t, "orchestration-restart-marker-client",
		"orchestration-serial-service", "restart-post-only-marker")
	requireViolationFromSource(ctx, t, "orchestration-serial-policy",
		"orchestration-restart-marker-client", "orchestration-serial-server")
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

func (s *istioPullFixture) clientCertificateRotation(
	ctx context.Context,
	t *testing.T,
	_ *envconf.Config,
) context.Context {
	t.Helper()
	require.Equal(t, s.ztunnel.Spec.NodeName, s.workerAgent.Spec.NodeName,
		"certificate denial must be observed against the destination worker agent")
	// The server CA and server leaf remain unchanged: only client CA A is
	// removed, and the same agent must reject the current holder's cert A.
	rotationStart := metav1.NewTime(time.Now())
	require.NoError(t, rotateAgentClientTrustToB(ctx, s.client, s.namespace, s.certificates),
		"replace agent client trust A with B while preserving server identity and CA")
	requireEventuallyControllerTLSDenial(ctx, t, s.client, s.namespace, s.leader.pod, s.workerAgent, rotationStart)
	s.requireSameLeader(ctx, t)

	// Allow bounded Secret projection and the puller's retry backoff before the
	// next scrape proves cert B works without restarting the manager.
	require.NoError(t, rotateControllerClientToB(ctx, s.client, s.namespace, s.certificates),
		"project controller client certificate B")
	warmupUntilAttributedWithin(
		ctx,
		t,
		"orchestration-serial-policy",
		"orchestration-cert-marker-client",
		"orchestration-serial-server",
		"orchestration-serial-service",
		"certificate-b-marker",
		2*defaultOperationTimeout,
	)
	s.requireSameLeader(ctx, t)
	return ctx
}

type orchestrationCertificateSet struct {
	controllerA orchestrationSecretData
	controllerB orchestrationSecretData
	agentA      orchestrationSecretData
	agentB      orchestrationSecretData
}

type orchestrationSecretData struct {
	ca   []byte
	cert []byte
	key  []byte
}

type orchestrationCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func createOrchestrationWorkloads(
	ctx context.Context,
	t *testing.T,
	workerNode, controlPlaneNode string,
) {
	t.Helper()
	namespace := getNamespace(ctx)
	createOrchestrationServer(ctx, t, namespace, "orchestration-serial-server", workerNode)
	createOrchestrationServer(ctx, t, namespace, "orchestration-handover-server", controlPlaneNode)
	for _, name := range []string{
		"orchestration-serial-client",
		"orchestration-handover-client",
		"orchestration-handover-post-client",
		"orchestration-restart-marker-client",
		"orchestration-cert-marker-client",
	} {
		labels := map[string]string{"app": name}
		createCorrelationDeployment(ctx, t, name, labels, labels, []string{"sleep", "10d"})
	}
	for _, name := range []string{"orchestration-serial-server", "orchestration-handover-server"} {
		require.NoError(t, getSecurityV1Alpha1Client(ctx).Create(ctx, &corev1.Service{
			Name: strings.Replace(name, "server", "service", 1), Namespace: namespace,
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": name},
				Ports: []corev1.ServicePort{
					{Name: "tcp-echo", Protocol: corev1.ProtocolTCP, Port: 18080, TargetPort: intstr.FromInt32(18080)},
				},
			},
		}), "create Service for %q", name)
		require.NoError(t, wait.For(conditions.New(getSecurityV1Alpha1Client(ctx)).DeploymentAvailable(name, namespace),
			wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout)), "wait for server Deployment %q", name)
	}
}

func createOrchestrationServer(
	ctx context.Context,
	t *testing.T,
	namespace, name, node string,
) {
	t.Helper()
	replicas := int32(1)
	labels := map[string]string{"app": name}
	deployment := &appsv1.Deployment{
		Name: name, Namespace: namespace,
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{corev1.LabelHostname: node},
					Tolerations: []corev1.Toleration{
						{
							Key:      "node-role.kubernetes.io/control-plane",
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoSchedule,
						},
					},
					Containers: []corev1.Container{
						{
							Name:  name,
							Image: netshootImage,
							Command: []string{
								"sh",
								"-c",
								"set -eu; socat TCP-LISTEN:18080,reuseaddr,fork EXEC:/bin/cat >/tmp/e2e-tcp-listener.log 2>&1 & wait",
							},
						},
					},
				},
			},
		},
	}
	require.NoError(t, getSecurityV1Alpha1Client(ctx).Create(ctx, deployment), "create destination Deployment %q", name)
}

func createIstioOrchestrationPolicy(ctx context.Context, t *testing.T, name, targetDeployment string) {
	t.Helper()
	createCorrelationWNP(ctx, t, correlationWNPSpec{
		name:       name,
		targetName: targetDeployment,
		direction:  networkingv1.PolicyTypeIngress,
		mode:       v1alpha1.WorkloadNetworkPolicyModeMonitor,
		selector:   map[string]string{"app": targetDeployment},
	})
}

func waitForOrchestrationPolicies(ctx context.Context, t *testing.T) {
	t.Helper()
	for _, name := range []string{"orchestration-serial-policy", "orchestration-handover-policy"} {
		require.Eventually(t, func() bool {
			policy := &istiosecurityv1.AuthorizationPolicy{}
			if err := getSecurityV1Alpha1Client(ctx).Get(ctx, name, getNamespace(ctx), policy); err != nil {
				return false
			}
			return policy.Annotations[annotation.IoIstioDryRun.Name] == "true"
		}, defaultOperationTimeout, time.Second,
			"monitor AuthorizationPolicy %q was not rendered before traffic", name)
	}
}

func configureOrchestrationWorkloads(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace, controllerName, agentName, controllerSecret, agentSecret string,
) {
	t.Helper()
	deployment, err := clientset.AppsV1().Deployments(namespace).Get(ctx, controllerName, metav1.GetOptions{})
	require.NoError(t, err, "fetch controller Deployment")
	three := int32(3)
	deployment.Spec.Replicas = &three
	setControllerMaxInFlight(deployment, 1)
	require.NoError(t, replaceCertificateVolume(&deployment.Spec.Template.Spec, controllerSecret))
	_, err = clientset.AppsV1().Deployments(namespace).Update(ctx, deployment, metav1.UpdateOptions{})
	require.NoError(t, err, "configure three controller replicas and test gRPC trust volume")

	daemonSet, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, agentName, metav1.GetOptions{})
	require.NoError(t, err, "fetch agent DaemonSet")
	require.NoError(t, replaceCertificateVolume(&daemonSet.Spec.Template.Spec, agentSecret))
	_, err = clientset.AppsV1().DaemonSets(namespace).Update(ctx, daemonSet, metav1.UpdateOptions{})
	require.NoError(t, err, "configure test gRPC trust volume on agent DaemonSet")
}

func setControllerMaxInFlight(deployment *appsv1.Deployment, maximum int) {
	const argumentPrefix = "--agent-max-in-flight="
	for index, argument := range deployment.Spec.Template.Spec.Containers[0].Args {
		if strings.HasPrefix(argument, argumentPrefix) {
			deployment.Spec.Template.Spec.Containers[0].Args[index] = argumentPrefix + strconv.Itoa(maximum)
			return
		}
	}
	deployment.Spec.Template.Spec.Containers[0].Args = append(
		deployment.Spec.Template.Spec.Containers[0].Args, argumentPrefix+strconv.Itoa(maximum))
}

func replaceCertificateVolume(podSpec *corev1.PodSpec, secretName string) error {
	for index := range podSpec.Volumes {
		if podSpec.Volumes[index].Name == "grpc-certs" {
			podSpec.Volumes[index].VolumeSource = corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: secretName},
			}
			return nil
		}
	}
	return errors.New("chart gRPC certificate volume was missing")
}

func requireIstioOrchestrationNodes(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
) (string, string) {
	t.Helper()
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(t, err, "list Kind nodes")
	workerNode := ""
	controlPlaneNode := ""
	for _, node := range nodes.Items {
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			controlPlaneNode = node.Name
		} else if workerNode == "" {
			workerNode = node.Name
		}
	}
	require.NotEmpty(t, workerNode, "the Istio Kind cluster must have a worker node")
	require.NotEmpty(t, controlPlaneNode, "the Istio Kind cluster must have a control-plane node")
	require.NotEqual(t, workerNode, controlPlaneNode)
	return workerNode, controlPlaneNode
}

func requireNodeHasReadyDaemonSetPod(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	name, namespace, node string,
) corev1.Pod {
	t.Helper()
	var ready corev1.Pod
	daemonSet, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err, "get %s DaemonSet", name)
	selector := daemonSet.Spec.Selector.MatchLabels
	require.Eventually(t, func() bool {
		pods, listErr := clientset.CoreV1().
			Pods(namespace).
			List(ctx, metav1.ListOptions{LabelSelector: labels.Set(selector).AsSelector().String()})
		if listErr != nil {
			return false
		}
		for _, pod := range pods.Items {
			if pod.Spec.NodeName == node && pod.DeletionTimestamp == nil && isPodReady(&pod) {
				ready = pod
				return true
			}
		}
		return false
	}, defaultOperationTimeout, time.Second,
		"expected a Ready %s DaemonSet pod on node %q", name, node)
	return ready
}

func requireReadyAgentsOnNodes(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace, daemonSetName string,
	nodes []string,
) []corev1.Pod {
	t.Helper()
	daemonSet, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, daemonSetName, metav1.GetOptions{})
	require.NoError(t, err, "get agent DaemonSet")
	selector := labels.Set(daemonSet.Spec.Selector.MatchLabels).AsSelector().String()
	var agents []corev1.Pod
	require.Eventually(t, func() bool {
		currentDaemonSet, getErr := clientset.AppsV1().
			DaemonSets(namespace).
			Get(ctx, daemonSetName, metav1.GetOptions{})
		if getErr != nil || currentDaemonSet.Status.ObservedGeneration < currentDaemonSet.Generation ||
			currentDaemonSet.Status.UpdatedNumberScheduled != currentDaemonSet.Status.DesiredNumberScheduled ||
			currentDaemonSet.Status.NumberReady != currentDaemonSet.Status.DesiredNumberScheduled {
			return false
		}
		list, listErr := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if listErr != nil {
			return false
		}
		readyByNode := make(map[string]corev1.Pod)
		for index := range list.Items {
			pod := &list.Items[index]
			if pod.DeletionTimestamp == nil && isPodReady(pod) && isOwnedByDaemonSet(pod, daemonSetName) {
				readyByNode[pod.Spec.NodeName] = *pod
			}
		}
		agents = agents[:0]
		for _, node := range nodes {
			pod, found := readyByNode[node]
			if !found {
				return false
			}
			agents = append(agents, pod)
		}
		return true
	}, defaultOperationTimeout, time.Second,
		"release-owned agent DaemonSet did not become Ready on nodes %v", nodes)
	return agents
}

func requireReadyControllerPods(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace, deploymentName string,
	expected int32,
) []corev1.Pod {
	t.Helper()
	var pods []corev1.Pod
	require.Eventually(t, func() bool {
		deployment, err := clientset.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
		if err != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != expected ||
			deployment.Status.ObservedGeneration < deployment.Generation ||
			deployment.Status.UpdatedReplicas != expected || deployment.Status.ReadyReplicas != expected ||
			deployment.Status.AvailableReplicas != expected {
			return false
		}
		replicaSet := currentControllerReplicaSet(ctx, clientset, deployment)
		if replicaSet == nil || replicaSet.Status.ReadyReplicas != expected ||
			replicaSet.Status.AvailableReplicas != expected {
			return false
		}
		list, err := clientset.CoreV1().Pods(namespace).List(ctx,
			metav1.ListOptions{LabelSelector: labels.Set(replicaSet.Spec.Selector.MatchLabels).AsSelector().String()})
		if err != nil {
			return false
		}
		pods = pods[:0]
		for index := range list.Items {
			pod := &list.Items[index]
			if pod.DeletionTimestamp == nil && isPodReady(pod) && isOwnedByReplicaSet(pod, replicaSet.Name) {
				pods = append(pods, *pod)
			}
		}
		return int32(len(pods)) == expected
	}, defaultOperationTimeout, time.Second,
		"controller Deployment %q did not have exactly %d Ready current pods", deploymentName, expected)
	return pods
}

func currentControllerReplicaSet(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	deployment *appsv1.Deployment,
) *appsv1.ReplicaSet {
	list, err := clientset.AppsV1().ReplicaSets(deployment.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: labels.Set(deployment.Spec.Selector.MatchLabels).AsSelector().String()})
	if err != nil {
		return nil
	}
	for index := range list.Items {
		replicaSet := &list.Items[index]
		template := replicaSet.Spec.Template.DeepCopy()
		delete(template.Labels, appsv1.DefaultDeploymentUniqueLabelKey)
		if metav1.IsControlledBy(replicaSet, deployment) &&
			apiequality.Semantic.DeepEqual(*template, deployment.Spec.Template) {
			return replicaSet
		}
	}
	return nil
}

func isOwnedByReplicaSet(pod *corev1.Pod, name string) bool {
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "ReplicaSet" && owner.Name == name && owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

func isPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func requireRenewedControllerLease(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace string,
	pods []corev1.Pod,
	previousRenewal *metav1.MicroTime,
) coordinationv1.Lease {
	t.Helper()
	var firstRenewal *metav1.MicroTime
	firstHolder := ""
	var stable coordinationv1.Lease
	require.Eventually(t, func() bool {
		lease, err := clientset.CoordinationV1().Leases(namespace).Get(ctx, istioAgentLeaseName, metav1.GetOptions{})
		if err != nil || lease.Spec.HolderIdentity == nil || lease.Spec.RenewTime == nil {
			return false
		}
		holder := *lease.Spec.HolderIdentity
		index, found := holderPodIndex(pods, holder)
		if !found {
			return false
		}
		currentPod, err := clientset.CoreV1().Pods(namespace).Get(ctx, pods[index].Name, metav1.GetOptions{})
		if err != nil || currentPod.UID != pods[index].UID || !isPodReady(currentPod) {
			return false
		}
		if firstRenewal == nil || firstHolder != holder {
			firstRenewal = lease.Spec.RenewTime.DeepCopy()
			firstHolder = holder
			return false
		}
		if previousRenewal != nil && !lease.Spec.RenewTime.After(previousRenewal.Time) {
			return false
		}
		if !lease.Spec.RenewTime.After(firstRenewal.Time) {
			return false
		}
		stable = *lease
		return true
	}, 35*time.Second, time.Second,
		"controller Lease %q did not renew twice under the same live holder", istioAgentLeaseName)
	// Observe the same holder again; the Lease period is longer than this check.
	stableHolder := *stable.Spec.HolderIdentity
	time.Sleep(2 * time.Second)
	again := readControllerLease(ctx, t, clientset, namespace)
	require.Equal(t, stableHolder, *again.Spec.HolderIdentity, "controller Lease holder changed while being observed")
	require.False(t, again.Spec.RenewTime.Time.Before(stable.Spec.RenewTime.Time),
		"controller Lease renewal timestamp moved backwards")
	return again
}

func requireRenewedControllerLeaseOnLivePod(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace, deploymentName, previousHolder string,
	previousRenewal *metav1.MicroTime,
) (coordinationv1.Lease, corev1.Pod, []corev1.Pod) {
	t.Helper()
	var firstHolder string
	var firstRenewal *metav1.MicroTime
	var stable coordinationv1.Lease
	var successor corev1.Pod
	var livePods []corev1.Pod
	require.Eventually(t, func() bool {
		lease, err := clientset.CoordinationV1().Leases(namespace).Get(ctx, istioAgentLeaseName, metav1.GetOptions{})
		if err != nil || lease.Spec.HolderIdentity == nil || lease.Spec.RenewTime == nil ||
			*lease.Spec.HolderIdentity == previousHolder {
			return false
		}
		pods, err := liveReadyControllerPods(ctx, clientset, namespace, deploymentName)
		if err != nil {
			return false
		}
		index, found := holderPodIndex(pods, *lease.Spec.HolderIdentity)
		if !found {
			return false
		}
		if firstRenewal == nil || firstHolder != *lease.Spec.HolderIdentity {
			firstHolder = *lease.Spec.HolderIdentity
			firstRenewal = lease.Spec.RenewTime.DeepCopy()
			return false
		}
		if previousRenewal != nil && !lease.Spec.RenewTime.After(previousRenewal.Time) {
			return false
		}
		if !lease.Spec.RenewTime.After(firstRenewal.Time) {
			return false
		}
		stable = *lease
		successor = pods[index]
		livePods = pods
		return true
	}, 35*time.Second, time.Second,
		"controller Lease %q did not renew twice under a live successor Pod", istioAgentLeaseName)
	return stable, successor, livePods
}

func liveReadyControllerPods(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace, deploymentName string,
) ([]corev1.Pod, error) {
	deployment, err := clientset.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	replicaSet := currentControllerReplicaSet(ctx, clientset, deployment)
	if replicaSet == nil {
		return nil, errors.New("current controller ReplicaSet is not available")
	}
	list, err := clientset.CoreV1().Pods(namespace).List(ctx,
		metav1.ListOptions{LabelSelector: labels.Set(replicaSet.Spec.Selector.MatchLabels).AsSelector().String()})
	if err != nil {
		return nil, err
	}
	var pods []corev1.Pod
	for index := range list.Items {
		pod := &list.Items[index]
		if pod.DeletionTimestamp == nil && isPodReady(pod) && isOwnedByReplicaSet(pod, replicaSet.Name) {
			pods = append(pods, *pod)
		}
	}
	return pods, nil
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
	requireReadyControllerPods(ctx, t, s.client, s.namespace, s.controller, 3)
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
	require.Eventually(t, func() bool {
		stdout, _, err := execInDeploymentRaw(
			ctx,
			clientDeployment,
			[]string{"sh", "-c", "cat " + progressFile + " 2>/dev/null || true"},
		)
		return err == nil && len(successfulEchoLines(stdout)) >= minimum
	}, 20*time.Second, 300*time.Millisecond, "handover burst did not reach %d successful sends", minimum)
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
	require.Eventually(t, func() bool {
		stdout, _, err := execInDeploymentRaw(ctx, clientDeployment,
			[]string{"sh", "-c", "cat " + progressFile + " 2>/dev/null || true"})
		return err == nil && latestSuccessfulAttemptID(stdout) > previousID
	}, defaultOperationTimeout, 500*time.Millisecond,
		"finite handover sender did not produce a successful attempt above %d", previousID)
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
	require.Eventually(t, func() bool {
		policy, err := readOrchestrationPolicy(ctx, name)
		return err == nil && policy.Status.ViolationCount == expected
	}, defaultOperationTimeout, time.Second,
		"WorkloadNetworkPolicy %q did not reach exact violationCount=%d", name, expected)
	waitForSettledViolationCount(ctx, t, name)
	require.Equal(t, expected, getOrchestrationViolationCount(ctx, t, name),
		"WorkloadNetworkPolicy %q violationCount changed during the scrape/status quiet window", name)
}

func waitForSettledViolationCount(ctx context.Context, t *testing.T, name string) int64 {
	t.Helper()
	var stableCount int64
	var unchangedSince time.Time
	require.Eventually(t, func() bool {
		policy, err := readOrchestrationPolicy(ctx, name)
		if err != nil {
			return false
		}
		if unchangedSince.IsZero() || policy.Status.ViolationCount != stableCount {
			stableCount = policy.Status.ViolationCount
			unchangedSince = time.Now()
			return false
		}
		return time.Since(unchangedSince) >= istioAgentStatusQuietFor
	}, 2*defaultOperationTimeout, time.Second,
		"WorkloadNetworkPolicy %q violationCount did not settle", name)
	return stableCount
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

func warmupUntilAttributed(
	ctx context.Context,
	t *testing.T,
	policyName, sourceName, destinationName, service, payloadPrefix string,
) {
	t.Helper()
	warmupUntilAttributedWithin(ctx, t, policyName, sourceName, destinationName, service, payloadPrefix,
		defaultOperationTimeout)
}

func warmupUntilAttributedWithin(
	ctx context.Context,
	t *testing.T,
	policyName, sourceName, destinationName, service, payloadPrefix string,
	timeout time.Duration,
) {
	t.Helper()
	requireNoOrchestrationViolation(ctx, t, policyName, sourceName, destinationName)
	deadline := time.Now().Add(timeout)
	lastStatus := "not read"
	for attempt := 0; time.Now().Before(deadline) && ctx.Err() == nil; attempt++ {
		payload := fmt.Sprintf("%s-%d", payloadPrefix, attempt)
		if err := trySendEcho(ctx, sourceName, service, payload); err != nil {
			t.Logf("unmeasured warm-up send %q failed: %v", payload, err)
			continue
		}
		if waitForWarmupObservation(ctx, policyName, sourceName, destinationName, deadline, &lastStatus) {
			return
		}
	}
	t.Fatalf("no attributed warm-up observation for %q to %q; last status: %s", sourceName, destinationName, lastStatus)
}

func waitForWarmupObservation(
	ctx context.Context,
	policyName, sourceName, destinationName string,
	deadline time.Time,
	lastStatus *string,
) bool {
	observationDeadline := time.Now().Add(30 * time.Second)
	if deadline.Before(observationDeadline) {
		observationDeadline = deadline
	}
	for time.Now().Before(observationDeadline) {
		policy, err := readOrchestrationPolicy(ctx, policyName)
		if err == nil {
			*lastStatus = orchestrationStatusSummary(policy)
			if findExpectedOrchestrationViolation(
				policy.Status.Violations, getNamespace(ctx), policyName, sourceName, destinationName,
			) != nil {
				return true
			}
		} else {
			*lastStatus = err.Error()
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false
}

func orchestrationStatusSummary(policy v1alpha1.WorkloadNetworkPolicy) string {
	tuples := make([]string, 0, len(policy.Status.Violations))
	for _, violation := range policy.Status.Violations {
		tuples = append(tuples, fmt.Sprintf("%s/%s->%s/%s@%s", violation.Source.Namespace,
			violation.Source.OwnerName, violation.Dest.Namespace, violation.Dest.OwnerName,
			violation.Timestamp.UTC().Format(time.RFC3339)))
	}
	return fmt.Sprintf("violationCount=%d tuples=%v", policy.Status.ViolationCount, tuples)
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
	require.Eventually(t, func() bool {
		policy, err := readOrchestrationPolicy(ctx, policyName)
		return err == nil && findExpectedOrchestrationViolation(
			policy.Status.Violations, getNamespace(ctx), policyName, sourceName, destinationName) != nil
	}, defaultOperationTimeout, time.Second,
		"WorkloadNetworkPolicy %q did not contain source %q to destination %q", policyName, sourceName, destinationName)
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
	require.Eventually(t, func() bool {
		current, found, err := orchestrationViolationTimestamp(ctx, policyName, sourceName, destinationName)
		return err == nil && found && current.After(previous.Time)
	}, defaultOperationTimeout, time.Second,
		"WorkloadNetworkPolicy %q did not advance timestamp for %s to %s beyond %s",
		policyName, sourceName, destinationName, previous.Time.UTC().Format(time.RFC3339))
}

func requireViolationCountIncrease(ctx context.Context, t *testing.T, name string, previous int64) int64 {
	t.Helper()
	var current int64
	require.Eventually(t, func() bool {
		policy, err := readOrchestrationPolicy(ctx, name)
		if err != nil {
			return false
		}
		current = policy.Status.ViolationCount
		return current > previous
	}, defaultOperationTimeout, time.Second,
		"WorkloadNetworkPolicy %q made no progress beyond count %d", name, previous)
	return current
}

func findAgentOnNode(t *testing.T, agents []corev1.Pod, node string) corev1.Pod {
	t.Helper()
	for _, pod := range agents {
		if pod.Spec.NodeName == node {
			return pod
		}
	}
	t.Fatalf("no ready agent pod on node %q", node)
	return corev1.Pod{}
}

func requireReplacementAgent(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace, daemonSetName, node string,
	oldUID types.UID,
) corev1.Pod {
	t.Helper()
	var replacement corev1.Pod
	daemonSet, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, daemonSetName, metav1.GetOptions{})
	require.NoError(t, err)
	selector := labels.Set(daemonSet.Spec.Selector.MatchLabels).AsSelector().String()
	require.Eventually(t, func() bool {
		currentDaemonSet, getErr := clientset.AppsV1().
			DaemonSets(namespace).
			Get(ctx, daemonSetName, metav1.GetOptions{})
		if getErr != nil || currentDaemonSet.Status.ObservedGeneration < currentDaemonSet.Generation ||
			currentDaemonSet.Status.UpdatedNumberScheduled != currentDaemonSet.Status.DesiredNumberScheduled {
			return false
		}
		list, listErr := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if listErr != nil {
			return false
		}
		replacement = corev1.Pod{}
		oldUIDPresent := false
		for index := range list.Items {
			pod := &list.Items[index]
			if pod.UID == oldUID {
				oldUIDPresent = true
			}
			if pod.Spec.NodeName == node && pod.UID != oldUID && pod.DeletionTimestamp == nil &&
				isPodReady(pod) && isOwnedByDaemonSet(pod, daemonSetName) {
				replacement = *pod
			}
		}
		return !oldUIDPresent && replacement.UID != ""
	}, defaultOperationTimeout, time.Second,
		"agent DaemonSet did not replace UID %q on node %q", oldUID, node)
	return replacement
}

func isOwnedByDaemonSet(pod *corev1.Pod, name string) bool {
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "DaemonSet" && owner.Name == name && owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

func requireEventuallyAgentTailerStarted(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace string,
	agent corev1.Pod,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		current, err := clientset.CoreV1().Pods(namespace).Get(ctx, agent.Name, metav1.GetOptions{})
		if err != nil || current.UID != agent.UID {
			return false
		}
		logs, err := readPodLogs(ctx, clientset, *current, "agent", nil)
		return err == nil && strings.Contains(logs, "Started tailer")
	}, defaultOperationTimeout, time.Second, "replacement agent did not start its tailer")
}

func requireLeaderDiscoveredAgentUID(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	leader, agent corev1.Pod,
) {
	t.Helper()
	require.Eventually(
		t,
		func() bool {
			logs, err := readPodLogs(ctx, clientset, leader, "manager", nil)
			return err == nil && hasStructuredLogRecord(logs, func(entry map[string]any) bool {
				return entry["msg"] == "Discovered Istio agent Pod" &&
					entry["pod"] == agent.Namespace+"/"+agent.Name && entry["uid"] == string(agent.UID)
			})
		},
		defaultOperationTimeout,
		time.Second,
		"unchanged leader did not record one discovery entry for replacement agent Pod %q UID %q",
		agent.Name,
		agent.UID,
	)
}

func makeOrchestrationCertificates(t *testing.T, namespace string) orchestrationCertificateSet {
	t.Helper()
	serverCA := makeOrchestrationCA(t, "orchestration-server-ca")
	clientCA := makeOrchestrationCA(t, "orchestration-client-ca-a")
	rotatedClientCA := makeOrchestrationCA(t, "orchestration-client-ca-b")
	serverCert, serverKey := issueOrchestrationLeaf(t, serverCA, []string{"*." + namespace}, x509.ExtKeyUsageServerAuth)
	controllerSAN := loadSuiteConfig().releaseName + "-controller"
	controllerCertA, controllerKeyA := issueOrchestrationLeaf(t, clientCA,
		[]string{controllerSAN}, x509.ExtKeyUsageClientAuth)
	controllerCertB, controllerKeyB := issueOrchestrationLeaf(t, rotatedClientCA,
		[]string{controllerSAN}, x509.ExtKeyUsageClientAuth)
	trustedA := append(append([]byte{}, serverCA.pem...), clientCA.pem...)
	trustedB := append(append([]byte{}, serverCA.pem...), rotatedClientCA.pem...)
	return orchestrationCertificateSet{
		controllerA: orchestrationSecretData{ca: trustedA, cert: controllerCertA, key: controllerKeyA},
		controllerB: orchestrationSecretData{ca: trustedB, cert: controllerCertB, key: controllerKeyB},
		agentA:      orchestrationSecretData{ca: trustedA, cert: serverCert, key: serverKey},
		agentB:      orchestrationSecretData{ca: trustedB, cert: serverCert, key: serverKey},
	}
}

func makeOrchestrationCA(t *testing.T, commonName string) orchestrationCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate test-only certificate authority key")
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	require.NoError(t, err, "generate test-only CA serial")
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	require.NoError(t, err, "create test-only CA certificate")
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return orchestrationCA{cert: parsed, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func issueOrchestrationLeaf(
	t *testing.T,
	ca orchestrationCA,
	dnsNames []string,
	usage x509.ExtKeyUsage,
) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate test-only leaf key")
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	require.NoError(t, err, "generate test-only leaf serial")
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(90 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err, "issue test-only leaf certificate")
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err, "encode test-only leaf key")
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
}

func createOrchestrationSecret(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace, name string,
	data orchestrationSecretData,
) (types.UID, error) {
	secret, err := clientset.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		Name: name,
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"ca.crt": data.ca, "tls.crt": data.cert, "tls.key": data.key},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return secret.UID, nil
}

func rotateAgentClientTrustToB(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace string,
	certificates orchestrationCertificateSet,
) error {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, istioAgentServerCert, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret.Data["ca.crt"] = certificates.agentB.ca
	_, err = clientset.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func rotateControllerClientToB(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace string,
	certificates orchestrationCertificateSet,
) error {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, istioAgentControllerCert, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret.Data["ca.crt"] = certificates.controllerB.ca
	secret.Data["tls.crt"] = certificates.controllerB.cert
	secret.Data["tls.key"] = certificates.controllerB.key
	_, err = clientset.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func requireEventuallyControllerTLSDenial(
	ctx context.Context,
	t *testing.T,
	clientset *kubernetes.Clientset,
	namespace string,
	leader, destinationAgent corev1.Pod,
	started metav1.Time,
) {
	t.Helper()
	var lastLogs string
	endpoint := destinationAgent.Status.PodIP + ":50052"
	podKey := destinationAgent.Namespace + "/" + destinationAgent.Name
	require.Eventually(t, func() bool {
		logs, err := readPodLogs(ctx, clientset, leader, "manager", &started)
		if err != nil {
			return false
		}
		lastLogs = logs
		return hasStructuredLogRecord(logs, func(entry map[string]any) bool {
			return entry["msg"] == "Istio agent poll failed, retrying" && entry["pod"] == podKey &&
				entry["endpoint"] == endpoint && isRemoteClientCertificateDenial(entry["error"])
		})
	}, 2*defaultOperationTimeout, 2*time.Second,
		"leader did not record one TLS client-certificate rejection for worker agent %q at %q; logs: %s",
		podKey, endpoint, lastLogs)
	lease := readControllerLease(ctx, t, clientset, namespace)
	require.Equal(t, leader.Name, findHolderPod(t, []corev1.Pod{leader}, *lease.Spec.HolderIdentity).Name,
		"TLS rejection must be observed while the same controller remains Lease holder")
}

func isRemoteClientCertificateDenial(value any) bool {
	errorText := strings.ToLower(fmt.Sprint(value))
	return strings.Contains(errorText, "remote error: tls: bad certificate") ||
		strings.Contains(errorText, "remote error: tls: certificate required")
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

func restoreDeploymentSpec(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace, name string,
	spec *appsv1.DeploymentSpec,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		current.Spec = *spec.DeepCopy()
		_, err = clientset.AppsV1().Deployments(namespace).Update(ctx, current, metav1.UpdateOptions{})
		return err
	})
}

func restoreDaemonSetSpec(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	namespace, name string,
	spec *appsv1.DaemonSetSpec,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := clientset.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		current.Spec = *spec.DeepCopy()
		_, err = clientset.AppsV1().DaemonSets(namespace).Update(ctx, current, metav1.UpdateOptions{})
		return err
	})
}
