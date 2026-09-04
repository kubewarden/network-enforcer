package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/kubewarden/network-enforcer/internal/istio"
)

// SetupPodIPIndexer registers the status.podIP field index on the manager's
// cache. It must be called before mgr.Start, since field indexes have to be
// registered before the informer cache is started. The index is keyed and
// populated by istio.PodIPIndexField / istio.IndexPodByIP, which the Istio
// enricher queries to resolve a source peer IP to its owning pod.
func SetupPodIPIndexer(ctx context.Context, mgr manager.Manager) error {
	if err := mgr.GetFieldIndexer().
		IndexField(ctx, &corev1.Pod{}, istio.PodIPIndexField, istio.IndexPodByIP); err != nil {
		return fmt.Errorf("indexing pods by %s: %w", istio.PodIPIndexField, err)
	}
	return nil
}
