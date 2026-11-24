package scraper

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	k8stypes "k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
)

const (
	learningAggregationWindow       = 10 * time.Second
	maxLearningAggregationEntries   = 50_000
	maxLearningAggregationKeyBytes  = 512
	learningLookupsSuppressedMetric = "network_enforcer_istio_learning_workload_lookups_suppressed_total"
)

func registerLearningLookupsSuppressed(reg prometheus.Registerer) (prometheus.Counter, error) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: learningLookupsSuppressedMetric,
		Help: "Number of Istio learning workload lookups avoided by accepted-event aggregation.",
	})
	if err := reg.Register(counter); err != nil {
		if alreadyRegistered, ok := errors.AsType[prometheus.AlreadyRegisteredError](err); ok {
			if existing, isCounter := alreadyRegistered.ExistingCollector.(prometheus.Counter); isCounter {
				return existing, nil
			}
		}
		return nil, fmt.Errorf("registering Istio learning aggregation metric: %w", err)
	}
	return counter, nil
}

type learningPodKey struct {
	namespace string
	name      string
}

type learningWorkloadKey struct {
	namespace string
	kind      securityv1alpha1.WorkloadKind
	name      string
	uid       k8stypes.UID
}

type learningTupleKey struct {
	workload learningWorkloadKey
	identity string
	port     int32
}

type learningPodMemo struct {
	workload  learningWorkloadKey
	ambiguous bool
}

type learningEnqueueResult string

const (
	learningEnqueueRejected  learningEnqueueResult = "rejected"
	learningEnqueueAccepted  learningEnqueueResult = "accepted"
	learningEnqueueDuplicate learningEnqueueResult = "duplicate"
)

type learningAggregation struct {
	mu sync.Mutex

	windowStarted time.Time
	generation    uint64
	pods          map[learningPodKey]learningPodMemo
	accepted      map[learningTupleKey]struct{}
}

func newLearningAggregation() *learningAggregation {
	return &learningAggregation{}
}

func (a *learningAggregation) rotate(now time.Time) {
	if a.generation != 0 && now.Sub(a.windowStarted) < learningAggregationWindow {
		return
	}

	a.windowStarted = now
	a.generation++
	a.pods = make(map[learningPodKey]learningPodMemo)
	a.accepted = make(map[learningTupleKey]struct{})
}

func (a *learningAggregation) beginResolution(
	now func() time.Time,
	pod learningPodKey,
	identity string,
	port int32,
) (uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.rotate(now())
	generation := a.generation
	memo, found := a.pods[pod]
	if !found || memo.ambiguous {
		return generation, false
	}
	_, found = a.accepted[learningTupleKey{workload: memo.workload, identity: identity, port: port}]
	return generation, found
}

func (a *learningAggregation) enqueueResolved(
	now func() time.Time,
	generation uint64,
	pod learningPodKey,
	tuple learningTupleKey,
	enqueue func() bool,
) learningEnqueueResult {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.rotate(now())
	if generation == a.generation {
		memo, found := a.pods[pod]
		switch {
		case !found && len(a.pods) < maxLearningAggregationEntries:
			a.pods[pod] = learningPodMemo{workload: tuple.workload}
		case found && !memo.ambiguous && memo.workload != tuple.workload:
			a.pods[pod] = learningPodMemo{ambiguous: true}
		}
	}
	if _, tupleAlreadyAccepted := a.accepted[tuple]; tupleAlreadyAccepted {
		return learningEnqueueDuplicate
	}

	if !enqueue() {
		return learningEnqueueRejected
	}
	if generation == a.generation && len(a.accepted) < maxLearningAggregationEntries {
		a.accepted[tuple] = struct{}{}
	}
	return learningEnqueueAccepted
}

func isLearningAggregationKeyTooLarge(pod learningPodKey, identity string) bool {
	return len(pod.namespace)+len(pod.name)+len(identity) > maxLearningAggregationKeyBytes
}
