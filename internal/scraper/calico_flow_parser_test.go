package scraper

import (
	"errors"
	"testing"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	pb "github.com/rancher-sandbox/network-enforcer/internal/scraper/goldmane"
	"github.com/rancher-sandbox/network-enforcer/internal/testutil"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	defaultCalicoTestNamespace = "default"
	defaultGoldmaneEndpoint    = "goldmane.calico-system.svc:7443"
)

func calicoTestFlowTime() time.Time {
	return time.Date(2026, 8, 24, 10, 11, 12, 0, time.UTC)
}

func calicoFlowResult(key *pb.FlowKey) *pb.FlowResult {
	return &pb.FlowResult{Flow: &pb.Flow{Key: key, StartTime: calicoTestFlowTime().Unix()}}
}

func allowDstWorkloadKey() *pb.FlowKey {
	return &pb.FlowKey{
		Action:          pb.Action_Allow,
		Reporter:        pb.Reporter_Dst,
		SourceType:      pb.EndpointType_WorkloadEndpoint,
		DestType:        pb.EndpointType_WorkloadEndpoint,
		SourceName:      "http-client-abc123-*",
		SourceNamespace: defaultCalicoTestNamespace,
		DestName:        "http-server-def456-*",
		DestNamespace:   defaultCalicoTestNamespace,
		DestPort:        18080,
		Proto:           "TCP",
	}
}

func denyDstWorkloadKey() *pb.FlowKey {
	key := allowDstWorkloadKey()
	key.Action = pb.Action_Deny
	return key
}

func denySrcWorkloadKey() *pb.FlowKey {
	key := denyDstWorkloadKey()
	key.Reporter = pb.Reporter_Src
	return key
}

func calicoProtectObservation(
	direction networkingv1.PolicyType,
	protocol corev1.Protocol,
	dstPort int32,
	denyingName, denyingNamespace string,
) violation.Observation {
	return violation.Observation{
		Provider:  securityv1alpha1.PolicyBackendKubernetes,
		Direction: direction,
		Timestamp: metav1.NewTime(calicoTestFlowTime()),
		Source: securityv1alpha1.WorkloadRef{
			Namespace: defaultCalicoTestNamespace,
			OwnerName: "http-client-abc123-*",
		},
		Dest: securityv1alpha1.WorkloadRef{
			Namespace: defaultCalicoTestNamespace,
			OwnerName: "http-server-def456-*",
		},
		Protocol:               protocol,
		DstPort:                dstPort,
		Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		DenyingPolicyNamespace: denyingNamespace,
		DenyingPolicyName:      denyingName,
	}
}

func TestParseCalicoFlow(t *testing.T) {
	t.Parallel()

	testProcessFlowOutcomeError := processFlowError(errors.New("example error, not relevant"))

	tests := []struct {
		name              string
		flow              *pb.FlowResult
		processFlowResult processFlowResult
	}{
		{
			name:              "nil_flow",
			flow:              nil,
			processFlowResult: testProcessFlowOutcomeError,
		},
		{
			name:              "empty_flow",
			flow:              &pb.FlowResult{},
			processFlowResult: testProcessFlowOutcomeError,
		},
		{
			name: "src_reporter_allow_is_skipped",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.Reporter = pb.Reporter_Src
				return key
			}()),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "pass_action_is_skipped",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.Action = pb.Action_Pass
				return key
			}()),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "deny_dst_flow_records_ingress_violation",
			flow: calicoFlowResult(denyDstWorkloadKey()),
			processFlowResult: processFlowRecordViolation(calicoProtectObservation(
				networkingv1.PolicyTypeIngress,
				corev1.ProtocolTCP,
				18080,
				"",
				"",
			)),
		},
		{
			name: "deny_src_flow_records_egress_violation",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := denySrcWorkloadKey()
				key.DestPort = 18081
				key.Proto = "UDP"
				return key
			}()),
			processFlowResult: processFlowRecordViolation(calicoProtectObservation(
				networkingv1.PolicyTypeEgress,
				corev1.ProtocolUDP,
				18081,
				"",
				"",
			)),
		},
		{
			name: "deny_flow_uses_networkpolicy_hit_name",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := denyDstWorkloadKey()
				key.Policies = &pb.PolicyTrace{
					EnforcedPolicies: []*pb.PolicyHit{{
						Kind:      pb.PolicyKind_NetworkPolicy,
						Namespace: defaultCalicoTestNamespace,
						Name:      "deployment-http-server-ingress",
						Action:    pb.Action_Deny,
					}},
				}
				return key
			}()),
			processFlowResult: processFlowRecordViolation(calicoProtectObservation(
				networkingv1.PolicyTypeIngress,
				corev1.ProtocolTCP,
				18080,
				"deployment-http-server-ingress",
				defaultCalicoTestNamespace,
			)),
		},
		{
			name: "deny_flow_uses_end_of_tier_trigger_name",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := denySrcWorkloadKey()
				key.Policies = &pb.PolicyTrace{
					EnforcedPolicies: []*pb.PolicyHit{{
						Kind:   pb.PolicyKind_EndOfTier,
						Action: pb.Action_Deny,
						Trigger: &pb.PolicyHit{
							Kind:      pb.PolicyKind_NetworkPolicy,
							Namespace: defaultCalicoTestNamespace,
							Name:      "deployment-http-client-egress",
						},
					}},
				}
				return key
			}()),
			processFlowResult: processFlowRecordViolation(calicoProtectObservation(
				networkingv1.PolicyTypeEgress,
				corev1.ProtocolTCP,
				18080,
				"deployment-http-client-egress",
				defaultCalicoTestNamespace,
			)),
		},
		{
			name: "non_workload_destination_is_skipped",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.DestType = pb.EndpointType_Network
				return key
			}()),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "unsupported_protocol",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.Proto = "ICMP"
				return key
			}()),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "valid_tcp_flow",
			flow: calicoFlowResult(allowDstWorkloadKey()),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "http-client-abc123-*",
				},
				Dest: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "http-server-def456-*",
				},
				DstPort:  18080,
				Protocol: corev1.ProtocolTCP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "uses_dest_port_not_service_port",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.DestPort = 18080
				key.DestServicePort = 80
				return key
			}()),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "http-client-abc123-*",
				},
				Dest: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "http-server-def456-*",
				},
				DstPort:  18080,
				Protocol: corev1.ProtocolTCP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "valid_udp_flow",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.DestPort = 18081
				key.Proto = "UDP"
				return key
			}()),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "http-client-abc123-*",
				},
				Dest: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "http-server-def456-*",
				},
				DstPort:  18081,
				Protocol: corev1.ProtocolUDP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := parseCalicoFlow(tc.flow)
			require.Equal(t, tc.processFlowResult.outcome, result.outcome)
			if tc.processFlowResult.outcome == processFlowOutcomeEnqueue {
				require.Equal(t, tc.processFlowResult.event, result.event)
			}
			if tc.processFlowResult.outcome == processFlowOutcomeViolation {
				require.Equal(t, tc.processFlowResult.observation, result.observation)
			}
		})
	}
}

func TestProcessCalicoFlowResolvesWorkloadsWithFakeClient(t *testing.T) {
	t.Parallel()

	clientPod := &corev1.Pod{
		Name:         "http-client-abc123-xyz",
		Namespace:    defaultCalicoTestNamespace,
		GenerateName: "http-client-abc123-",
		Labels:       map[string]string{appsv1.DefaultDeploymentUniqueLabelKey: "abc123", "app": "http-client"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       string(securityv1alpha1.WorkloadKindReplicaSet),
			Name:       "http-client-abc123",
			UID:        "client-rs",
			Controller: new(true),
		}},
	}
	serverPod := &corev1.Pod{
		Name:         "http-server-def456-xyz",
		Namespace:    defaultCalicoTestNamespace,
		GenerateName: "http-server-def456-",
		Labels:       map[string]string{appsv1.DefaultDeploymentUniqueLabelKey: "def456", "app": "http-server"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       string(securityv1alpha1.WorkloadKindReplicaSet),
			Name:       "http-server-def456",
			UID:        "server-rs",
			Controller: new(true),
		}},
	}
	jobPod := &corev1.Pod{
		Name:         "batch-job-pq2qc",
		Namespace:    defaultCalicoTestNamespace,
		GenerateName: "batch-job-",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "batch/v1",
			Kind:       "Job",
			Name:       "batch-job",
			UID:        "job",
			Controller: new(true),
		}},
	}
	clientDeploy := &appsv1.Deployment{
		Name: "http-client", Namespace: defaultCalicoTestNamespace,
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-client"}},
		},
	}
	serverDeploy := &appsv1.Deployment{
		Name: "http-server", Namespace: defaultCalicoTestNamespace,
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}},
		},
	}
	stsPod := &corev1.Pod{
		Name:         "web-0",
		Namespace:    defaultCalicoTestNamespace,
		GenerateName: "web-",
		Labels:       map[string]string{"app": "web"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       string(securityv1alpha1.WorkloadKindStatefulSet),
			Name:       "web",
			UID:        "sts",
			Controller: new(true),
		}},
	}
	dsPod := &corev1.Pod{
		Name:         "fluent-bit-xyz",
		Namespace:    defaultCalicoTestNamespace,
		GenerateName: "fluent-bit-",
		Labels:       map[string]string{"app": "fluent-bit"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       string(securityv1alpha1.WorkloadKindDaemonSet),
			Name:       "fluent-bit",
			UID:        "ds",
			Controller: new(true),
		}},
	}
	sts := &appsv1.StatefulSet{
		Name: "web", Namespace: defaultCalicoTestNamespace,
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
	}
	ds := &appsv1.DaemonSet{
		Name: "fluent-bit", Namespace: defaultCalicoTestNamespace,
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "fluent-bit"}},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))

	sourcePolicyName := "deployment-http-client-egress"
	dstPolicyName := "deployment-http-server-ingress"
	sourceSelector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-client"}}
	dstSelector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "http-server"}}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			clientPod, serverPod, jobPod, clientDeploy, serverDeploy, stsPod, dsPod, sts, ds,
			&securityv1alpha1.WorkloadNetworkPolicy{
				Name: sourcePolicyName, Namespace: defaultCalicoTestNamespace,
				Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
					PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
						Backend:    securityv1alpha1.PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{PodSelector: sourceSelector},
					},
				},
			},
			&securityv1alpha1.WorkloadNetworkPolicy{
				Name: dstPolicyName, Namespace: defaultCalicoTestNamespace,
				Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
					PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
						Backend:    securityv1alpha1.PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{PodSelector: dstSelector},
					},
				},
			},
		).
		Build()

	s := NewCalicoScraper(CalicoScraperConfig{
		Client:               cl,
		Endpoint:             defaultGoldmaneEndpoint,
		EnqueueLearningEvent: func(types.LearningEvent) bool { return true },
		Logger:               testutil.NewTestLogger(t),
	})

	deploySource := &securityv1alpha1.WorkloadRef{
		Namespace: defaultCalicoTestNamespace,
		OwnerName: "http-client",
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		Selector:  sourceSelector,
	}
	deployDest := &securityv1alpha1.WorkloadRef{
		Namespace: defaultCalicoTestNamespace,
		OwnerName: "http-server",
		OwnerKind: securityv1alpha1.WorkloadKindDeployment,
		Selector:  dstSelector,
	}

	tests := []struct {
		name              string
		flow              *pb.FlowResult
		processFlowResult processFlowResult
	}{
		{
			name: "maps_generate_name_to_kubernetes_event",
			flow: calicoFlowResult(allowDstWorkloadKey()),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source:   deploySource,
				Dest:     deployDest,
				DstPort:  18080,
				Protocol: corev1.ProtocolTCP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "skips_unsupported_source_owner",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.SourceName = "batch-job-*"
				return key
			}()),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "skips_missing_dst",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.DestName = "http-server-missing-*"
				return key
			}()),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "skips_bare_pod_name",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.SourceName = "mypod"
				return key
			}()),
			processFlowResult: processFlowSkip(),
		},
		{
			name: "maps_statefulset_from_live_pod",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.SourceName = "web-*"
				return key
			}()),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "web",
					OwnerKind: securityv1alpha1.WorkloadKindStatefulSet,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				},
				Dest:     deployDest,
				DstPort:  18080,
				Protocol: corev1.ProtocolTCP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "maps_daemonset_from_live_pod",
			flow: calicoFlowResult(func() *pb.FlowKey {
				key := allowDstWorkloadKey()
				key.SourceName = "fluent-bit-*"
				return key
			}()),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCalicoTestNamespace,
					OwnerName: "fluent-bit",
					OwnerKind: securityv1alpha1.WorkloadKindDaemonSet,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "fluent-bit"}},
				},
				Dest:     deployDest,
				DstPort:  18080,
				Protocol: corev1.ProtocolTCP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "deny_ingress_resolves_violation_policy_on_destination",
			flow: calicoFlowResult(denyDstWorkloadKey()),
			processFlowResult: processFlowRecordViolation(violation.Observation{
				Provider:               securityv1alpha1.PolicyBackendKubernetes,
				Direction:              networkingv1.PolicyTypeIngress,
				Timestamp:              metav1.NewTime(calicoTestFlowTime()),
				Source:                 *deploySource,
				Dest:                   *deployDest,
				Protocol:               corev1.ProtocolTCP,
				DstPort:                18080,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DenyingPolicyNamespace: defaultCalicoTestNamespace,
				DenyingPolicyName:      dstPolicyName,
			}),
		},
		{
			name: "deny_egress_resolves_violation_policy_on_source",
			flow: calicoFlowResult(denySrcWorkloadKey()),
			processFlowResult: processFlowRecordViolation(violation.Observation{
				Provider:               securityv1alpha1.PolicyBackendKubernetes,
				Direction:              networkingv1.PolicyTypeEgress,
				Timestamp:              metav1.NewTime(calicoTestFlowTime()),
				Source:                 *deploySource,
				Dest:                   *deployDest,
				Protocol:               corev1.ProtocolTCP,
				DstPort:                18080,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DenyingPolicyNamespace: defaultCalicoTestNamespace,
				DenyingPolicyName:      sourcePolicyName,
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := resolveParsedFlow(
				t.Context(),
				s.resolve,
				bindResolveDenyingPolicy(s.Client),
				parseCalicoFlow(tc.flow),
			)
			require.Equal(t, tc.processFlowResult.outcome, result.outcome)
			if tc.processFlowResult.outcome == processFlowOutcomeEnqueue {
				require.Equal(t, tc.processFlowResult.event, result.event)
			}
			if tc.processFlowResult.outcome == processFlowOutcomeViolation {
				require.Equal(t, tc.processFlowResult.observation, result.observation)
			}
		})
	}
}
