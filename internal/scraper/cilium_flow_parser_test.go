package scraper

import (
	"errors"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	hubbleObserver "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/api/v1/relay"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/testutil"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/violation"
)

const defaultCiliumTestNamespace = "default"

func flowResponse(flow *flowpb.Flow) *hubbleObserver.GetFlowsResponse {
	return &hubbleObserver.GetFlowsResponse{
		ResponseTypes: &hubbleObserver.GetFlowsResponse_Flow{Flow: flow},
	}
}

func testProcessFlowOutcomeError() processFlowResult {
	return processFlowResult{
		outcome: processFlowOutcomeError,
		err:     errors.New("example error, not relevant"),
	}
}

func TestParseCiliumFlow(t *testing.T) {
	t.Parallel()

	flowTimestamp := time.Date(2026, 8, 24, 10, 11, 12, 0, time.UTC)

	endpoint := func(name, kind string) *hubbleObserver.Endpoint {
		return &hubbleObserver.Endpoint{
			Namespace: defaultCiliumTestNamespace,
			Workloads: []*flowpb.Workload{{
				Name: name,
				Kind: kind,
			}},
		}
	}

	tests := []struct {
		name              string
		flow              *flowpb.Flow
		processFlowResult processFlowResult
	}{
		{
			name: "reply_flow_is_skipped",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(true),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "dropped_reason_different_from_policy_denied",
			flow: &flowpb.Flow{
				// DROPPED events don't have the `is_reply` field
				// IsReply:
				Time:             timestamppb.New(flowTimestamp),
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   hubbleObserver.DropReason_INVALID_IPV6_EXTENSION_HEADER,
				TrafficDirection: hubbleObserver.TrafficDirection_INGRESS,
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:           endpoint("source-deploy", "Deployment"),
				Destination:      endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "dropped_ingress_flow_records_violation",
			flow: &flowpb.Flow{
				// DROPPED events don't have the `is_reply` field
				// IsReply:
				Time:             timestamppb.New(flowTimestamp),
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   hubbleObserver.DropReason_POLICY_DENIED,
				TrafficDirection: hubbleObserver.TrafficDirection_INGRESS,
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:           endpoint("source-deploy", "Deployment"),
				Destination:      endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowRecordViolation(violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendKubernetes,
				Direction: networkingv1.PolicyTypeIngress,
				Timestamp: metav1.NewTime(flowTimestamp),
				Source: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "source-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "dest-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
				},
				Protocol:               corev1.ProtocolTCP,
				DstPort:                8080,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DenyingPolicyNamespace: "",
				DenyingPolicyName:      "",
			}),
		},
		{
			name: "dropped_egress_flow_records_violation",
			flow: &flowpb.Flow{
				Time:             timestamppb.New(flowTimestamp),
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   hubbleObserver.DropReason_POLICY_DENY,
				TrafficDirection: hubbleObserver.TrafficDirection_EGRESS,
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 5353}}},
				Source:           endpoint("source-sts", "StatefulSet"),
				Destination:      endpoint("dest-ds", "DaemonSet"),
			},
			processFlowResult: processFlowRecordViolation(violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendKubernetes,
				Direction: networkingv1.PolicyTypeEgress,
				Timestamp: metav1.NewTime(flowTimestamp),
				Source: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "source-sts",
					OwnerKind: securityv1alpha1.WorkloadKindStatefulSet,
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "dest-ds",
					OwnerKind: securityv1alpha1.WorkloadKindDaemonSet,
				},
				Protocol:               corev1.ProtocolUDP,
				DstPort:                5353,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DenyingPolicyNamespace: "",
				DenyingPolicyName:      "",
			}),
		},
		{
			name: "dropped_flow_unknown_direction_errors",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   hubbleObserver.DropReason_POLICY_DENY,
				TrafficDirection: hubbleObserver.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN,
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:           endpoint("source-deploy", "Deployment"),
				Destination:      endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name: "unsupported_protocol",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{}}},
				Source:      endpoint("source-deploy", "Deployment"),
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "unsupported_source_workload_kind",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:      endpoint("source-job", "Job"),
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "source_pod_workload_is_kept_for_later_resolution",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:  endpoint("source-deploy", "Deployment"),
				Destination: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					PodName:   "dest-pod",
				},
			},
			processFlowResult: processFlowEnqueue(
				types.LearningEvent{
					Source: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "source-deploy",
						OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					},
					Dest: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "dest-pod",
						OwnerKind: securityv1alpha1.WorkloadKindPod,
					},
					DstPort:  8080,
					Protocol: corev1.ProtocolTCP,
					Backend:  securityv1alpha1.PolicyBackendKubernetes,
				},
			),
		},
		{
			name: "endpoint_without_workload_is_skipped",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					// No workload associated will cause a skip.
				},
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "endpoint_with_multiple_workloads",
			flow: &flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{
						{Name: "source-1", Kind: "Deployment"},
						{Name: "source-2", Kind: "Deployment"},
					},
				},
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name: "valid_tcp_flow",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source:      endpoint("source-deploy", "Deployment"),
				Destination: endpoint("dest-deploy", "Deployment"),
			},
			processFlowResult: processFlowEnqueue(
				types.LearningEvent{
					Source: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "source-deploy",
						OwnerKind: securityv1alpha1.WorkloadKindDeployment,
						Identity:  "",
					},
					Dest: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "dest-deploy",
						OwnerKind: securityv1alpha1.WorkloadKindDeployment,
						Identity:  "",
					},
					DstPort:  8080,
					Protocol: corev1.ProtocolTCP,
					Backend:  securityv1alpha1.PolicyBackendKubernetes,
				},
			),
		},
		{
			name: "valid_udp_flow",
			flow: &flowpb.Flow{
				IsReply:     wrapperspb.Bool(false),
				L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 5353}}},
				Source:      endpoint("source-sts", "StatefulSet"),
				Destination: endpoint("dest-ds", "DaemonSet"),
			},
			processFlowResult: processFlowEnqueue(
				types.LearningEvent{
					Source: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "source-sts",
						OwnerKind: securityv1alpha1.WorkloadKindStatefulSet,
					},
					Dest: &securityv1alpha1.WorkloadRef{
						Namespace: defaultCiliumTestNamespace,
						OwnerName: "dest-ds",
						OwnerKind: securityv1alpha1.WorkloadKindDaemonSet,
					},
					DstPort:  5353,
					Protocol: corev1.ProtocolUDP,
					Backend:  securityv1alpha1.PolicyBackendKubernetes,
				},
			),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := parseCiliumFlowResponse(tc.flow)
			require.Equal(t, tc.processFlowResult.outcome, result.outcome)
			// we assert the learning event if we have it
			if tc.processFlowResult.outcome == processFlowOutcomeEnqueue {
				require.Equal(t, tc.processFlowResult.event, result.event)
			}
			if tc.processFlowResult.outcome == processFlowOutcomeViolation {
				require.Equal(t, tc.processFlowResult.observation, result.observation)
			}
		})
	}
}

func TestProcessFlowResolvesSelectorsWithFakeClient(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))

	flowTimestamp := time.Date(2026, 8, 24, 10, 11, 12, 0, time.UTC)
	sourcePolicyName := "source-policy"
	dstPolicyName := "dest-policy"
	sourceSelector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "source"}}
	dstSelector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "dest"}}
	controller := true
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&appsv1.Deployment{
				Name: "source-deploy", Namespace: defaultCiliumTestNamespace,
				Spec: appsv1.DeploymentSpec{
					Selector: &sourceSelector,
				},
			},
			&appsv1.Deployment{
				Name: "dest-deploy", Namespace: defaultCiliumTestNamespace,
				Spec: appsv1.DeploymentSpec{
					Selector: &dstSelector,
				},
			},
			&appsv1.DaemonSet{
				Name: "dns-daemon", Namespace: "kube-system",
				Spec: appsv1.DaemonSetSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
				},
			},
			&corev1.Pod{
				Name:      "coredns-pod",
				Namespace: "kube-system",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1",
					Kind:       "DaemonSet",
					Name:       "dns-daemon",
					Controller: &controller,
				}},
			},
			&corev1.Pod{
				Name:      "standalone-pod",
				Namespace: "kube-system",
			},
			&securityv1alpha1.WorkloadNetworkPolicy{
				Name: sourcePolicyName, Namespace: defaultCiliumTestNamespace,
				Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
					PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
						Backend: securityv1alpha1.PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: sourceSelector,
						},
					},
				},
			},
			&securityv1alpha1.WorkloadNetworkPolicy{
				Name: dstPolicyName, Namespace: defaultCiliumTestNamespace,
				Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
					PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
						Backend: securityv1alpha1.PolicyBackendKubernetes,
						Kubernetes: &networkingv1.NetworkPolicySpec{
							PodSelector: dstSelector,
						},
					},
				},
			},
		).Build()

	s := NewCiliumScraper(CiliumScraperConfig{
		Client: cl,
		Logger: testutil.NewTestLogger(t),
	})

	tests := []struct {
		name              string
		flow              *hubbleObserver.GetFlowsResponse
		processFlowResult processFlowResult
	}{
		{
			name: "both_workloads_present",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "dest-deploy", Kind: "Deployment"}},
				},
			}),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "source-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "source"}},
				},
				Dest: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "dest-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "dest"}},
				},
				DstPort:  8080,
				Protocol: corev1.ProtocolTCP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "resolve_dest_pod_to_workload",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				// this is a pod associated to a daemonset we have in cache.
				Destination: &hubbleObserver.Endpoint{
					Namespace: "kube-system",
					PodName:   "coredns-pod",
				},
			}),
			processFlowResult: processFlowEnqueue(types.LearningEvent{
				Source: &securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "source-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "source"}},
				},
				Dest: &securityv1alpha1.WorkloadRef{
					Namespace: "kube-system",
					OwnerName: "dns-daemon",
					OwnerKind: securityv1alpha1.WorkloadKindDaemonSet,
					Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
				},
				DstPort:  53,
				Protocol: corev1.ProtocolUDP,
				Backend:  securityv1alpha1.PolicyBackendKubernetes,
			}),
		},
		{
			name: "dropped_ingress_flow_resolves_violation_policy_on_destination",
			flow: flowResponse(&flowpb.Flow{
				Time:             timestamppb.New(flowTimestamp),
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   hubbleObserver.DropReason_POLICY_DENY,
				TrafficDirection: hubbleObserver.TrafficDirection_INGRESS,
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "dest-deploy", Kind: "Deployment"}},
				},
			}),
			processFlowResult: processFlowRecordViolation(violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendKubernetes,
				Direction: networkingv1.PolicyTypeIngress,
				Timestamp: metav1.NewTime(flowTimestamp),
				Source: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "source-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  sourceSelector,
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "dest-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  dstSelector,
				},
				Protocol:               corev1.ProtocolTCP,
				DstPort:                8080,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DenyingPolicyNamespace: defaultCiliumTestNamespace,
				DenyingPolicyName:      dstPolicyName,
			}),
		},
		{
			name: "dropped_egress_flow_resolves_violation_policy_on_source",
			flow: flowResponse(&flowpb.Flow{
				Time:             timestamppb.New(flowTimestamp),
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   hubbleObserver.DropReason_POLICY_DENY,
				TrafficDirection: hubbleObserver.TrafficDirection_EGRESS,
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "dest-deploy", Kind: "Deployment"}},
				},
			}),
			processFlowResult: processFlowRecordViolation(violation.Observation{
				Provider:  securityv1alpha1.PolicyBackendKubernetes,
				Direction: networkingv1.PolicyTypeEgress,
				Timestamp: metav1.NewTime(flowTimestamp),
				Source: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "source-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  sourceSelector,
				},
				Dest: securityv1alpha1.WorkloadRef{
					Namespace: defaultCiliumTestNamespace,
					OwnerName: "dest-deploy",
					OwnerKind: securityv1alpha1.WorkloadKindDeployment,
					Selector:  dstSelector,
				},
				Protocol:               corev1.ProtocolTCP,
				DstPort:                8080,
				Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DenyingPolicyNamespace: defaultCiliumTestNamespace,
				DenyingPolicyName:      sourcePolicyName,
			}),
		},
		{
			name: "missing_dst_selector",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 8080}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "dest-deploy-not-present", Kind: "Deployment"}},
				},
			}),
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name: "cannot_resolve_dest_pod",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: "kube-system",
					PodName:   "does-not-exist",
				},
			}),
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name: "dest_pod_is_standalone_skip",
			flow: flowResponse(&flowpb.Flow{
				IsReply: wrapperspb.Bool(false),
				L4:      &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}},
				Source: &hubbleObserver.Endpoint{
					Namespace: defaultCiliumTestNamespace,
					Workloads: []*flowpb.Workload{{Name: "source-deploy", Kind: "Deployment"}},
				},
				Destination: &hubbleObserver.Endpoint{
					Namespace: "kube-system",
					PodName:   "standalone-pod",
				},
			}),
			processFlowResult: processFlowSkip(),
		},
		{
			name:              "nil_flow_response",
			flow:              nil,
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name:              "nil_payload_flow_response",
			flow:              flowResponse(nil),
			processFlowResult: testProcessFlowOutcomeError(),
		},
		{
			name: "lost_events_is_skipped",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_LostEvents{
					LostEvents: &flowpb.LostEvent{NumEventsLost: 5},
				},
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name: "node_status_is_skipped",
			flow: &hubbleObserver.GetFlowsResponse{
				ResponseTypes: &hubbleObserver.GetFlowsResponse_NodeStatus{
					NodeStatus: &relay.NodeStatusEvent{},
				},
			},
			processFlowResult: processFlowSkip(),
		},
		{
			name:              "empty_response_type_is_skipped",
			flow:              &hubbleObserver.GetFlowsResponse{},
			processFlowResult: processFlowSkip(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := s.processFlow(t.Context(), tc.flow)
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
