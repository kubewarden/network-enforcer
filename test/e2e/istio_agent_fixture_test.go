package e2e_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"istio.io/api/annotation"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	pullNodeRoleLabel  = "e2e.network-enforcer.io/role" // clusters/istio.yaml
	clientLeafLifetime = 2 * time.Minute
)

// The disposable Kind cluster has one worker and one tainted control plane.
// Each hosts an agent, a ztunnel and a separate destination for the fairness test.
type istioPullFixture struct {
	client                                    *kubernetes.Clientset
	namespace, controller, controllerSelector string
	agentDS                                   *appsv1.DaemonSet
	r                                         *resources.Resources // scoped to the Helm release namespace
	ztunnel, workerAgent                      corev1.Pod
	leader                                    orchestrationLeader
}

func (s *istioPullFixture) setup(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, istioOrchestrationLimit)
	t.Cleanup(cancel)
	// Feature teardown is skipped on fail-fast; restore shared resources before deleting the namespace.
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), defaultOperationTimeout)
		defer stop()
		teardownTestNamespace(cleanupCtx, t, cfg)
	})
	ctx = labelNamespaceAmbient(ctx, t, cfg)
	suite := getSuiteConfig(ctx)
	s.namespace, s.controller = suite.releaseNS, suite.releaseName+"-controller-manager"
	client := cfg.Client()
	var err error
	s.client, err = kubernetes.NewForConfig(client.RESTConfig())
	require.NoError(t, err)
	s.r = client.Resources(s.namespace)
	s.configureController(ctx, t)

	worker := s.createPullWorkloads(ctx, t)
	s.agentDS = &appsv1.DaemonSet{Name: suite.releaseName + "-agent", Namespace: s.namespace}
	s.waitForAgents(ctx, t)
	s.workerAgent = s.agentOnNode(ctx, t, worker, "")
	// The suite already waits for the ztunnel DaemonSet. Select the pod whose logs witness the burst.
	zt := &appsv1.DaemonSet{Name: "ztunnel", Namespace: istioNamespace}
	require.NoError(t, s.r.Get(ctx, zt.Name, zt.Namespace, zt))
	list, err := s.client.CoreV1().Pods(zt.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: metav1.FormatLabelSelector(zt.Spec.Selector), FieldSelector: "spec.nodeName=" + worker,
	})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	s.ztunnel = list.Items[0]

	s.readyControllerPods(ctx, t)
	s.leader = s.renewedLeader(ctx, t, "", nil)
	return ctx
}

func (s *istioPullFixture) configureController(ctx context.Context, t *testing.T) {
	t.Helper()
	deployments := s.client.AppsV1().Deployments(s.namespace)
	dep, err := deployments.Get(ctx, s.controller, metav1.GetOptions{})
	require.NoError(t, err)
	s.controllerSelector = metav1.FormatLabelSelector(dep.Spec.Selector)
	original := dep.Spec.DeepCopy()
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		restoreErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			current, getErr := deployments.Get(cleanupCtx, s.controller, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			current.Spec = *original
			_, updateErr := deployments.Update(cleanupCtx, current, metav1.UpdateOptions{})
			return updateErr
		})
		require.NoError(t, restoreErr, "restore controller Deployment")
		s.waitForControllerRollout(cleanupCtx, t, ptr.Deref(original.Replicas, 1))
	})
	dep.Spec.Replicas = new(int32(3))
	container := &dep.Spec.Template.Spec.Containers[0]
	container.Args = append(container.Args, "--agent-max-in-flight=1")
	// The chart mounts a per-pod CSI leaf, not a Certificate resource that cmctl renew can target.
	// Shorten only the controller's agent-hop credential; keep webhook and agent trust untouched.
	volumes := dep.Spec.Template.Spec.Volumes
	i := slices.IndexFunc(volumes, func(v corev1.Volume) bool { return v.Name == "grpc-certs" })
	require.NotEqual(t, -1, i, "missing controller gRPC certificate mount")
	csi := volumes[i].CSI
	require.NotNil(t, csi)
	require.Equal(t, "csi.cert-manager.io", csi.Driver)
	csi.VolumeAttributes["csi.cert-manager.io/duration"] = clientLeafLifetime.String()
	_, err = deployments.Update(ctx, dep, metav1.UpdateOptions{})
	require.NoError(t, err, "configure controller replicas, pull limit and CSI leaf lifetime")
}

func (s *istioPullFixture) waitForControllerRollout(ctx context.Context, t *testing.T, expected int32) {
	t.Helper()
	// Available alone may refer to the old revision during a rolling update.
	dep := &appsv1.Deployment{Name: s.controller, Namespace: s.namespace}
	ready := conditions.New(s.r).ResourceMatch(dep, func(_ k8s.Object) bool {
		st := dep.Status
		return ptr.Deref(dep.Spec.Replicas, 1) == expected && st.ObservedGeneration >= dep.Generation &&
			st.UpdatedReplicas == expected && st.Replicas == expected &&
			st.AvailableReplicas == expected && st.ReadyReplicas == expected
	})
	require.NoError(
		t,
		wait.For(ready, wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout), wait.WithImmediate()),
		"controller %s did not roll out %d replicas",
		dep.Name,
		expected,
	)
}

func (s *istioPullFixture) readyControllerPods(ctx context.Context, t *testing.T) []corev1.Pod {
	t.Helper()
	s.waitForControllerRollout(ctx, t, 3)
	pods, err := s.liveControllers(ctx)
	require.NoError(t, err)
	require.Len(t, pods, 3, "expected three ready pods of the rolled-out controller")
	return pods
}

func (s *istioPullFixture) liveControllers(ctx context.Context) ([]corev1.Pod, error) {
	list, err := s.client.CoreV1().Pods(s.namespace).List(ctx, metav1.ListOptions{LabelSelector: s.controllerSelector})
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(list.Items, func(p corev1.Pod) bool { return !pullPodReady(&p) }), nil
}

func pullPodReady(p *corev1.Pod) bool {
	return p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning &&
		slices.ContainsFunc(p.Status.Conditions, func(c corev1.PodCondition) bool {
			return c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue
		})
}

// On handover the replacement controller need not be ready yet: the evidence we need
// is a different live holder renewing its Lease while traffic is still flowing.
func (s *istioPullFixture) renewedLeader(
	ctx context.Context,
	t *testing.T,
	oldHolder string,
	oldRenewal *metav1.MicroTime,
) orchestrationLeader {
	t.Helper()
	var holder string
	var firstRenewal *metav1.MicroTime
	var leader orchestrationLeader
	err := wait.For(func(ctx context.Context) (bool, error) {
		lease, err := s.client.CoordinationV1().Leases(s.namespace).Get(ctx, istioAgentLeaseName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		id := ptr.Deref(lease.Spec.HolderIdentity, "")
		when := lease.Spec.RenewTime
		if id == "" || id == oldHolder || when == nil {
			return false, nil
		}
		pods, err := s.liveControllers(ctx)
		if err != nil {
			return false, err
		}
		i, found := holderPodIndex(pods, id)
		if !found {
			return false, nil
		}
		if id != holder {
			holder, firstRenewal = id, when
			return false, nil
		}
		if !when.After(firstRenewal.Time) || (oldRenewal != nil && !when.After(oldRenewal.Time)) {
			return false, nil
		}
		leader = orchestrationLeader{lease: *lease, pods: pods, pod: pods[i]}
		return true, nil
	}, wait.WithContext(ctx), wait.WithTimeout(35*time.Second), wait.WithInterval(time.Second), wait.WithImmediate())
	require.NoError(
		t,
		err,
		"wait for a live controller to renew Lease %s (previous holder %q)",
		istioAgentLeaseName,
		oldHolder,
	)
	leader.process = requireManagerProcess(t, leader.pod)
	return leader
}

func (s *istioPullFixture) waitForAgents(ctx context.Context, t *testing.T) {
	t.Helper()
	require.NoError(
		t,
		wait.For(
			conditions.New(s.r).DaemonSetReady(s.agentDS),
			wait.WithContext(ctx),
			wait.WithTimeout(defaultOperationTimeout),
		),
		"wait for the agent DaemonSet",
	)
	require.EqualValues(t, 2, s.agentDS.Status.DesiredNumberScheduled, "the fixture needs one agent on each Kind node")
}

func (s *istioPullFixture) agentOnNode(ctx context.Context, t *testing.T, node, excludedUID string) corev1.Pod {
	t.Helper()
	var pod corev1.Pod
	match := func(obj k8s.Object) bool {
		p, ok := obj.(*corev1.Pod)
		if !ok || string(p.UID) == excludedUID || !metav1.IsControlledBy(p, s.agentDS) || !pullPodReady(p) {
			return false
		}
		pod = *p
		return true
	}
	ready := conditions.New(s.r).ResourceListMatchN(&corev1.PodList{}, 1, match,
		resources.WithLabelSelector(metav1.FormatLabelSelector(s.agentDS.Spec.Selector)),
		resources.WithFieldSelector("spec.nodeName="+node))
	require.NoError(
		t,
		wait.For(ready, wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout)),
		"wait for Ready agent on %s",
		node,
	)
	return pod
}

func (s *istioPullFixture) replaceWorkerAgent(ctx context.Context, t *testing.T) {
	t.Helper()
	old := s.workerAgent
	uid := old.UID
	err := s.client.CoreV1().
		Pods(s.namespace).
		Delete(ctx, old.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	require.NoError(t, err, "delete destination-node agent")
	require.NoError(
		t,
		wait.For(
			conditions.New(s.r).ResourceDeleted(old.DeepCopy()),
			wait.WithContext(ctx),
			wait.WithTimeout(defaultOperationTimeout),
		),
		"wait for old agent %s to disappear",
		old.Name,
	)
	s.workerAgent = s.agentOnNode(ctx, t, old.Spec.NodeName, string(old.UID))
	s.waitForAgents(ctx, t)
}

// Read public issued leaves only. CSI creates CertificateRequests owned by the pod
// for both webhook and pull credentials, so match the client SAN as well as the UID.
func (s *istioPullFixture) requireClientLeafAfter(
	ctx context.Context,
	t *testing.T,
	previousExpiry time.Time,
) time.Time {
	t.Helper()
	var expiry time.Time
	err := wait.For(func(ctx context.Context) (bool, error) {
		if !time.Now().After(previousExpiry) {
			return false, nil
		}
		var err error
		expiry, err = s.clientLeafExpiry(ctx)
		return expiry.After(time.Now()), err
	}, wait.WithContext(ctx), wait.WithTimeout(clientLeafLifetime+defaultOperationTimeout), wait.WithInterval(time.Second), wait.WithImmediate())
	require.NoError(t, err, "wait for a valid CSI client leaf for %s after %s", s.leader.pod.Name, previousExpiry)
	return expiry
}

func (s *istioPullFixture) clientLeafExpiry(ctx context.Context) (time.Time, error) {
	requests := &unstructured.UnstructuredList{}
	requests.SetGroupVersionKind(
		schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "CertificateRequestList"},
	)
	if err := s.r.List(ctx, requests); err != nil {
		return time.Time{}, err
	}
	var latest time.Time
	for _, req := range requests.Items {
		if !slices.ContainsFunc(
			req.GetOwnerReferences(),
			func(o metav1.OwnerReference) bool { return o.UID == s.leader.pod.UID },
		) {
			continue
		}
		encoded, _, err := unstructured.NestedString(req.Object, "status", "certificate")
		if err != nil {
			return time.Time{}, err
		}
		if encoded == "" { // not issued yet
			continue
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return time.Time{}, fmt.Errorf("decode CertificateRequest %s: %w", req.GetName(), err)
		}
		chain, err := cert.ParseCertsPEM(data)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse CertificateRequest %s: %w", req.GetName(), err)
		}
		leaf := chain[0]
		if slices.Contains(leaf.DNSNames, getSuiteConfig(ctx).releaseName+"-controller") &&
			leaf.NotAfter.After(latest) {
			latest = leaf.NotAfter
		}
	}
	return latest, nil
}

func (s *istioPullFixture) createPullWorkloads(ctx context.Context, t *testing.T) string {
	t.Helper()
	ns := getNamespace(ctx)
	r := getSecurityV1Alpha1Client(ctx)
	for _, role := range []struct{ prefix, nodeRole string }{
		{"orchestration-serial", "worker"},
		{"orchestration-handover", "control-plane"},
	} {
		name := role.prefix + "-server"
		labels := map[string]string{"app": name}
		dep := &appsv1.Deployment{Name: name, Namespace: ns, Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
				NodeSelector: map[string]string{pullNodeRoleLabel: role.nodeRole},
				Tolerations: []corev1.Toleration{
					{
						Key:      "node-role.kubernetes.io/control-plane",
						Operator: corev1.TolerationOpExists,
						Effect:   corev1.TaintEffectNoSchedule,
					},
				},
				Containers: []corev1.Container{
					{
						Name:    name,
						Image:   netshootImage,
						Command: []string{"socat", "TCP-LISTEN:18080,reuseaddr,fork", "EXEC:/bin/cat"},
					},
				},
			}},
		}}
		require.NoError(t, r.Create(ctx, dep))
		require.NoError(
			t,
			r.Create(ctx, &corev1.Service{Name: role.prefix + "-service", Namespace: ns, Spec: corev1.ServiceSpec{
				Selector: labels,
				Ports:    []corev1.ServicePort{{Name: "tcp-echo", Port: 18080, TargetPort: intstr.FromInt32(18080)}},
			}}),
		)
		createCorrelationWNP(ctx, t, correlationWNPSpec{
			name:       role.prefix + "-policy",
			targetName: name,
			direction:  networkingv1.PolicyTypeIngress,
			mode:       v1alpha1.WorkloadNetworkPolicyModeMonitor,
			selector:   labels,
		})
		c := conditions.New(r)
		require.NoError(
			t,
			wait.For(c.DeploymentAvailable(name, ns), wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout)),
		)
		policy := &istiosecurityv1.AuthorizationPolicy{
			Name: role.prefix + "-policy", Namespace: ns,
		}
		require.NoError(t, wait.For(c.ResourceMatch(policy, func(_ k8s.Object) bool {
			return policy.Annotations[annotation.IoIstioDryRun.Name] == "true"
		}), wait.WithContext(ctx), wait.WithTimeout(defaultOperationTimeout)), "wait for monitor AuthorizationPolicy %s", policy.Name)
	}
	for _, name := range []string{
		"orchestration-serial-client", "orchestration-handover-client", "orchestration-handover-post-client",
		"orchestration-restart-marker-client", "orchestration-cert-marker-client",
	} {
		labels := map[string]string{"app": name}
		createCorrelationDeployment(ctx, t, name, labels, labels, []string{"sleep", "10d"})
	}
	servers, err := s.client.CoreV1().
		Pods(ns).
		List(ctx, metav1.ListOptions{LabelSelector: "app=orchestration-serial-server"})
	require.NoError(t, err)
	require.Len(t, servers.Items, 1)
	return servers.Items[0].Spec.NodeName
}
