// Package istio holds the Istio-specific enrichment of network policy
// violations: resolving the source peer IP and destination pod name observed on
// the destination ztunnel back to their owning Kubernetes workloads and SPIFFE
// identities, and correlating ALLOW-miss violations to the owning
// WorkloadNetworkPolicy. It is Istio-specific because the reconstruction assumes
// Istio's ztunnel peer-address model and its SPIFFE principal form.
package istio

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
)

// Enricher resolves the source and destination workloads of an Istio violation
// from live pod state, using a status.podIP field index registered via
// controller.SetupPodIPIndexer, and correlates ALLOW-miss violations to the
// owning WorkloadNetworkPolicy. It is safe to use a nil *Enricher (or one with a
// nil client): Enrich is then a no-op passthrough.
type Enricher struct {
	client client.Client
}

// NewEnricher returns an Enricher backed by the given client. The client must
// read from a cache that has the PodIPIndexField and workload.WNPTargetIndexField
// indexes registered (see controller.SetupPodIPIndexer and controller.SetupWNPIndexer).
func NewEnricher(c client.Client) *Enricher {
	return &Enricher{client: c}
}

// Enrich resolves the source (by peer IP) and destination (by pod name) of an
// observation to their owning workloads and SPIFFE identities, and for an
// ALLOW-miss violation resolves the owning WorkloadNetworkPolicy so the
// controller can correlate it without a further pod lookup. Resolution is
// best-effort: on any lookup failure it logs and keeps the scraper-derived
// values, so enrichment never makes an observation worse than it was.
func (e *Enricher) Enrich(
	ctx context.Context,
	logger *slog.Logger,
	obs violation.Observation,
) violation.Observation {
	if e == nil || e.client == nil {
		return obs
	}

	if src, err := e.resolveSourceWorkload(ctx, obs); err != nil {
		logger.ErrorContext(ctx, "Failed to resolve violation source workload", "error", err)
	} else {
		obs.Source = src
	}

	// The destination workload and its owning WNP both derive from a single pod
	// fetch, so resolve the pod once and reuse it for both.
	if dstPod, err := e.resolveDestWorkload(ctx, obs); err != nil {
		logger.ErrorContext(ctx, "Failed to resolve violation destination workload", "error", err)
	} else {
		obs.Dest = workloadRefFromPod(dstPod)

		// When the event reports no policy, the owning WNP is not knowable from it.
		// Resolve it by matching the destination workload's (targetRef, Ingress),
		// since ztunnel enforces inbound only, and record it in the DenyingPolicy
		// fields. A reported policy is kept as is, and the controller verifies it
		// against the subject, counting a disagreement when its owning WNP targets
		// another workload. ztunnel enforces inbound only.
		if obs.DenyingPolicyName == "" {
			owner, ownerErr := workload.ResolveDenyingPolicy(ctx, e.client, &obs.Dest, networkingv1.PolicyTypeIngress)
			switch {
			case ownerErr != nil:
				logger.ErrorContext(ctx,
					"Failed to resolve owning WorkloadNetworkPolicy for ALLOW-miss correlation",
					"error", ownerErr)
			case owner.Name != "":
				obs.DenyingPolicyNamespace = owner.Namespace
				obs.DenyingPolicyName = owner.Name
			}
		}
	}

	return obs
}

// resolveDestWorkload fetches the destination pod named in the observation so the
// caller can resolve its owning workload and the WorkloadNetworkPolicy that
// selects it (both derive from the same pod).
//
// A non-nil error means there is no destination pod to resolve (the observation
// carries no destination namespace or pod name) or the pod could not be fetched;
// the caller logs it and keeps the scraper-derived destination.
func (e *Enricher) resolveDestWorkload(
	ctx context.Context,
	obs violation.Observation,
) (*corev1.Pod, error) {
	dstNamespace := obs.Dest.Namespace
	dstPod := obs.Dest.OwnerName
	if dstNamespace == "" || dstPod == "" {
		return nil, errors.New("observation has no destination pod to resolve")
	}

	var pod corev1.Pod
	if err := e.client.Get(ctx, types.NamespacedName{Namespace: dstNamespace, Name: dstPod}, &pod); err != nil {
		return nil, fmt.Errorf("fetching destination pod %s/%s: %w", dstNamespace, dstPod, err)
	}

	return &pod, nil
}

// peerIPFromAddr extracts the host from an Istio peer `ip:port` address. Istio
// emits this field in a precise `ip:port` form, so a value that does not parse
// is an unexpected format change rather than a valid no-op: it is returned as an
// error so the caller surfaces a clear failure instead of enriching silently.
func peerIPFromAddr(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("parsing source peer address %q: %w", addr, err)
	}
	return host, nil
}

// resolveSourceWorkload resolves the client (source) workload of an Istio
// violation from its peer address. Istio emits these events on the destination
// ztunnel and identifies the client only by `ip:port`, so the source is
// resolved by listing pods on the status.podIP field index.
//
// A non-nil error means the source could not be resolved to exactly one pod: the
// peer address was not in the expected `ip:port` form, the List errored, no pod
// carries the IP, or several do (e.g. host-network pods sharing the node IP). In
// every case the caller keeps the scraper-derived source and logs the failure
// once. On success the returned WorkloadRef is the single pod the peer IP
// resolved to.
//
// Because resolution is best-effort, the same logical flow can flip between
// resolved and unresolved across events (pod churn / pod not yet cached), so a
// source may be attributed for one event and left as the raw peer address for
// another.
func (e *Enricher) resolveSourceWorkload(
	ctx context.Context,
	obs violation.Observation,
) (securityv1alpha1.WorkloadRef, error) {
	peerIP, err := peerIPFromAddr(obs.Source.OwnerName)
	if err != nil {
		return securityv1alpha1.WorkloadRef{}, err
	}

	var podList corev1.PodList
	if err = e.client.List(ctx, &podList, client.MatchingFields{PodIPIndexField: peerIP}); err != nil {
		return securityv1alpha1.WorkloadRef{},
			fmt.Errorf("listing pods for source peer IP %s: %w", peerIP, err)
	}

	switch len(podList.Items) {
	case 1:
		return workloadRefFromPod(&podList.Items[0]), nil
	case 0:
		// The peer pod is not in the cache (not yet observed, already deleted, or
		// host-networked). Surface it as an error so the caller logs it once.
		return securityv1alpha1.WorkloadRef{},
			fmt.Errorf("no pod found for source peer IP %s", peerIP)
	default:
		// Multiple pods share the peer IP (e.g. host-network pods sharing the node
		// IP); we cannot attribute the source to one of them.
		return securityv1alpha1.WorkloadRef{},
			fmt.Errorf("%d pods found for source peer IP %s", len(podList.Items), peerIP)
	}
}

// workloadRefFromPod builds a WorkloadRef for a resolved pod (source or
// destination), including its Istio SPIFFE identity so it can drive rule
// clearing.
func workloadRefFromPod(pod *corev1.Pod) securityv1alpha1.WorkloadRef {
	wk := workload.GetNameAndKind(pod)
	wk.SetIdentity(pod.Spec.ServiceAccountName)
	return wk
}

func (e *Enricher) GetWorkloadRef(
	ctx context.Context,
	podNamespacedName types.NamespacedName,
) (securityv1alpha1.WorkloadRef, error) {
	return workload.Get(ctx, e.client, podNamespacedName)
}
