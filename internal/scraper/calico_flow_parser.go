package scraper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	pb "github.com/rancher-sandbox/network-enforcer/internal/scraper/goldmane"
	"github.com/rancher-sandbox/network-enforcer/internal/types"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	"github.com/rancher-sandbox/network-enforcer/internal/workload"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func parseCalicoFlow(flowResult *pb.FlowResult) processFlowResult {
	if flowResult == nil {
		return processFlowError(errors.New("found nil flow result"))
	}
	flow := flowResult.GetFlow()
	if flow == nil {
		return processFlowError(errors.New("found empty flow"))
	}
	key := flow.GetKey()
	if discardCalicoFlow(key) {
		return processFlowSkip()
	}

	dstPort, proto, err := extractCalicoPortAndProtocol(key)
	if err != nil {
		if errors.Is(err, errUnsupportedProtocol) {
			return processFlowSkip()
		}
		return processFlowError(err)
	}

	source := &securityv1alpha1.WorkloadRef{
		Namespace: key.GetSourceNamespace(),
		OwnerName: key.GetSourceName(),
	}
	dest := &securityv1alpha1.WorkloadRef{
		Namespace: key.GetDestNamespace(),
		OwnerName: key.GetDestName(),
	}

	if key.GetAction() == pb.Action_Deny {
		var direction networkingv1.PolicyType
		switch key.GetReporter() { //nolint:exhaustive // only Src/Dst map to policy directions
		case pb.Reporter_Src:
			direction = networkingv1.PolicyTypeEgress
		case pb.Reporter_Dst:
			direction = networkingv1.PolicyTypeIngress
		default:
			return processFlowError(errors.New("found violation flow with unknown reporter"))
		}

		denyingPolicyName, denyingPolicyNamespace := getDenyingPolicy(key)
		return processFlowRecordViolation(violation.Observation{
			Provider:               securityv1alpha1.PolicyBackendKubernetes,
			Direction:              direction,
			Timestamp:              calicoViolationTimestamp(flow),
			Source:                 *source,
			Dest:                   *dest,
			Protocol:               proto,
			DstPort:                dstPort,
			Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			DenyingPolicyNamespace: denyingPolicyNamespace,
			DenyingPolicyName:      denyingPolicyName,
		})
	}

	return processFlowEnqueue(types.LearningEvent{
		Source:   source,
		Dest:     dest,
		DstPort:  dstPort,
		Protocol: proto,
		Backend:  securityv1alpha1.PolicyBackendKubernetes,
	})
}

func calicoViolationTimestamp(flow *pb.Flow) metav1.Time {
	if ts := flow.GetStartTime(); ts > 0 {
		return metav1.NewTime(time.Unix(ts, 0).UTC())
	}
	return metav1.Now()
}

// getDenyingPolicy extracts the Kubernetes NetworkPolicy that denied the
// flow, when Goldmane reports it. For native K8s NetworkPolicy the hit may be
// a direct Deny or an EndOfTier Deny whose trigger is the selecting policy.
// We don't support CalicoNetworkPolicy and GlobalNetworkPolicy at the moment.
func getDenyingPolicy(key *pb.FlowKey) (string, string) {
	policyTrace := key.GetPolicies()
	if policyTrace == nil {
		return "", ""
	}
	for _, policy := range policyTrace.GetEnforcedPolicies() {
		if policy.GetAction() != pb.Action_Deny {
			continue
		}
		switch policy.GetKind() { //nolint:exhaustive // only Kubernetes NetworkPolicy is supported today
		case pb.PolicyKind_NetworkPolicy:
			if policy.GetName() != "" {
				return policy.GetName(), policy.GetNamespace()
			}
		case pb.PolicyKind_EndOfTier:
			trigger := policy.GetTrigger()
			if trigger != nil && trigger.GetKind() == pb.PolicyKind_NetworkPolicy && trigger.GetName() != "" {
				return trigger.GetName(), trigger.GetNamespace()
			}
		default:
		}
	}
	return "", ""
}

func discardCalicoFlow(key *pb.FlowKey) bool {
	if key == nil {
		return true
	}
	if key.GetSourceType() != pb.EndpointType_WorkloadEndpoint {
		return true
	}
	if key.GetDestType() != pb.EndpointType_WorkloadEndpoint {
		return true
	}
	if key.GetSourceName() == "" || key.GetSourceNamespace() == "" {
		return true
	}
	if key.GetDestName() == "" || key.GetDestNamespace() == "" {
		return true
	}
	port := key.GetDestPort()
	if port < minValidPort || port > maxValidPort {
		return true
	}
	switch key.GetAction() { //nolint:exhaustive // Pass and unspecified are unused
	case pb.Action_Allow:
		// Only destination-reported allows are used for learning to avoid duplicates.
		return key.GetReporter() != pb.Reporter_Dst
	case pb.Action_Deny:
		return key.GetReporter() != pb.Reporter_Src && key.GetReporter() != pb.Reporter_Dst
	default:
		return true
	}
}

func extractCalicoPortAndProtocol(key *pb.FlowKey) (int32, corev1.Protocol, error) {
	var proto corev1.Protocol
	switch strings.ToUpper(key.GetProto()) {
	case string(corev1.ProtocolTCP):
		proto = corev1.ProtocolTCP
	case string(corev1.ProtocolUDP):
		proto = corev1.ProtocolUDP
	default:
		return 0, "", fmt.Errorf("%w: %s", errUnsupportedProtocol, key.GetProto())
	}
	// `discardCalicoFlow` already dropped the flows with a port outside the
	// 1 - 65535 range, this conversion is just an extra safety net.
	dstPort, err := portToInt32(key.GetDestPort())
	if err != nil {
		return 0, "", err
	}
	return dstPort, proto, nil
}

// resolve maps a Goldmane aggregated name on ref into a supported WorkloadRef.
// OwnerName is GenerateName+"*" (for example "http-client-abc123-*"). A name
// without that suffix is a standalone pod, which we skip.
func (s *CalicoScraper) resolve(ctx context.Context, ref *securityv1alpha1.WorkloadRef) error {
	ownerName, ok := strings.CutSuffix(ref.OwnerName, "-*")
	if !ok || ownerName == "" {
		return errSkipWorkload
	}
	resolved, err := s.resolvePod(ctx, ref.Namespace, ownerName)
	if err != nil {
		return err
	}
	if !resolved.IsSupported() {
		return errSkipWorkload
	}
	*ref = resolved
	return nil
}

func (s *CalicoScraper) resolvePod(
	ctx context.Context,
	namespace, ownerName string,
) (securityv1alpha1.WorkloadRef, error) {
	generateName := ownerName + "-"
	var pods corev1.PodList
	if err := s.Client.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return securityv1alpha1.WorkloadRef{}, err
	}
	for idx := range pods.Items {
		pod := &pods.Items[idx]
		if pod.GenerateName != generateName && !strings.HasPrefix(pod.Name, generateName) {
			continue
		}
		return workload.Get(ctx, s.Client, k8stypes.NamespacedName{Namespace: pod.Namespace, Name: pod.Name})
	}
	return securityv1alpha1.WorkloadRef{}, nil
}
