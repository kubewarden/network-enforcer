package scraper

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/istio"
	"github.com/kubewarden/network-enforcer/internal/types"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

type countingLearningClient struct {
	client.Client

	podGets      atomic.Int32
	beforePodGet func()
	afterGet     func(client.Object)
}

func (c *countingLearningClient) Get(
	ctx context.Context,
	key client.ObjectKey,
	obj client.Object,
	opts ...client.GetOption,
) error {
	if _, ok := obj.(*corev1.Pod); ok {
		c.podGets.Add(1)
		if c.beforePodGet != nil {
			c.beforePodGet()
		}
	}
	err := c.Client.Get(ctx, key, obj, opts...)
	if err == nil && c.afterGet != nil {
		c.afterGet(obj)
	}
	return err
}

func newLearningObjects(
	podName, ownerName string,
	selector map[string]string,
) (*corev1.Pod, *appsv1.StatefulSet) {
	controller := true
	uid := k8stypes.UID(ownerName + "-uid")
	pod := &corev1.Pod{
		Namespace: "default",
		Name:      podName,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "StatefulSet",
			Name:       ownerName,
			UID:        uid,
			Controller: &controller,
		}},
	}
	statefulSet := &appsv1.StatefulSet{
		Namespace: "default", Name: ownerName, UID: uid,
		Spec: appsv1.StatefulSetSpec{Selector: &metav1.LabelSelector{MatchLabels: selector}},
	}
	return pod, statefulSet
}

func newLearningTestClient(t *testing.T, objects ...client.Object) *countingLearningClient {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	return &countingLearningClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()}
}

func newLearningEvent(podName, principal, port string) *agentv1.Event {
	namespace := "default"
	return &agentv1.Event{Kind: &agentv1.Event_Learn{Learn: &agentv1.LearnEvent{
		SourceIdentity:       "spiffe://" + principal,
		DestinationName:      &podName,
		DestinationNamespace: &namespace,
		DestinationPort:      port,
	}}}
}

func newLearningTestScraper(
	reader client.Client,
	enqueue LearningEnqueueFunc,
	registerer prometheus.Registerer,
) *IstioScraper {
	return NewIstioScraper(IstioScraperConfig{
		Logger:               slog.New(slog.DiscardHandler),
		Enricher:             istio.NewEnricher(reader),
		EnqueueLearningEvent: enqueue,
		MetricsRegisterer:    registerer,
	})
}

func TestIstioLearningAggregationWindowAndTupleDimensions(t *testing.T) {
	pod, owner := newLearningObjects("server-0", "server", map[string]string{"app": "server"})
	podOther, ownerOther := newLearningObjects("other-0", "other", map[string]string{"app": "other"})
	reader := newLearningTestClient(t, pod, owner, podOther, ownerOther)
	var learned []types.LearningEvent
	registry := prometheus.NewRegistry()
	scraper := newLearningTestScraper(reader, func(event types.LearningEvent) bool {
		learned = append(learned, event)
		return true
	}, registry)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	scraper.now = func() time.Time { return now }

	process := func(event *agentv1.Event) { scraper.processEvent(context.Background(), event) }
	process(newLearningEvent("server-0", "client", "08080"))
	process(newLearningEvent("server-0", "client", "8080"))
	require.Equal(t, int32(1), reader.podGets.Load(), "numeric ports share a tuple")
	require.Len(t, learned, 1)

	podReplica, _ := newLearningObjects("server-1", "server", map[string]string{"app": "server"})
	require.NoError(t, reader.Create(context.Background(), podReplica))
	process(newLearningEvent("server-1", "client", "8080"))
	require.Equal(t, int32(2), reader.podGets.Load(), "a cold replica needs one workload lookup")
	require.Len(t, learned, 1, "resolved replicas share a workload tuple")
	process(newLearningEvent("server-1", "client", "8080"))
	require.Equal(
		t,
		int32(2),
		reader.podGets.Load(),
		"the resolved replica is memoized even when its first tuple was already accepted",
	)
	process(newLearningEvent("other-0", "client", "8080"))
	require.Equal(t, int32(3), reader.podGets.Load())
	require.Len(t, learned, 2, "a different destination workload accepts the same principal and port")
	require.Equal(t, "other", learned[1].Dest.OwnerName)

	process(newLearningEvent("server-0", "other-client", "8080"))
	process(newLearningEvent("server-0", "client", "8081"))
	process(newLearningEvent("server-0", " client", "8080"))
	require.Equal(t, int32(6), reader.podGets.Load(), "principal and port are distinct tuple dimensions")
	require.Len(t, learned, 5)
	require.Equal(t, " client", learned[4].Source.Identity, "identity is cut after the SPIFFE prefix without trimming")

	now = now.Add(9 * time.Second)
	process(newLearningEvent("server-0", "client", "8080"))
	require.Equal(t, int32(6), reader.podGets.Load(), "the fixed window suppresses accepted tuples before expiry")
	now = now.Add(time.Second)
	process(newLearningEvent("server-0", "client", "8080"))
	require.Equal(t, int32(7), reader.podGets.Load(), "the tuple is resolved again at the ten-second boundary")
	require.Len(t, learned, 6)

	require.InDelta(t, 3, testutil.ToFloat64(scraper.learningLookupsSuppressed), 0.001)
	secondScraper := NewIstioScraper(IstioScraperConfig{MetricsRegisterer: registry})
	require.InDelta(t, 3, testutil.ToFloat64(secondScraper.learningLookupsSuppressed), 0.001)
}

func TestIstioLearningAggregationReownershipResolvesNewTupleAndSelector(t *testing.T) {
	pod, oldOwner := newLearningObjects("server-0", "old-server", map[string]string{"app": "old"})
	reader := newLearningTestClient(t, pod, oldOwner)
	var learned []types.LearningEvent
	scraper := newLearningTestScraper(reader, func(event types.LearningEvent) bool {
		learned = append(learned, event)
		return true
	}, nil)
	now := time.Now()
	scraper.now = func() time.Time { return now }
	ctx := context.Background()

	scraper.processEvent(ctx, newLearningEvent("server-0", "client", "8080"))
	newPod, newOwner := newLearningObjects("server-0", "new-server", map[string]string{"app": "new"})
	require.NoError(t, reader.Update(ctx, newPod))
	require.NoError(t, reader.Create(ctx, newOwner))

	scraper.processEvent(ctx, newLearningEvent("server-0", "client", "8080"))
	require.Equal(t, int32(1), reader.podGets.Load())

	scraper.processEvent(ctx, newLearningEvent("server-0", "new-client", "8080"))
	require.Equal(t, int32(2), reader.podGets.Load())
	require.Len(t, learned, 2)
	require.Equal(t, "new-server", learned[1].Dest.OwnerName)
	require.Equal(t, map[string]string{"app": "new"}, learned[1].Dest.Selector.MatchLabels)
}

func TestIstioLearningAggregationRecreatedOwnerUIDIsDistinct(t *testing.T) {
	pod, owner := newLearningObjects("server-old-0", "server", map[string]string{"app": "old"})
	reader := newLearningTestClient(t, pod, owner)
	var learned []types.LearningEvent
	scraper := newLearningTestScraper(reader, func(event types.LearningEvent) bool {
		learned = append(learned, event)
		return true
	}, nil)
	ctx := context.Background()
	event := newLearningEvent("server-old-0", "client", "8080")
	scraper.processEvent(ctx, event)

	newPod, recreatedOwner := newLearningObjects("server-new-0", "server", map[string]string{"app": "new"})
	newUID := k8stypes.UID("server-recreated-uid")
	newPod.OwnerReferences[0].UID = newUID
	recreatedOwner.UID = newUID
	require.NoError(t, reader.Create(ctx, newPod))
	require.NoError(t, reader.Update(ctx, recreatedOwner))
	scraper.processEvent(ctx, newLearningEvent("server-new-0", "client", "8080"))

	require.Len(t, learned, 2, "the same owner name with a new UID is a new aggregation target")
	require.Equal(t, map[string]string{"app": "new"}, learned[1].Dest.Selector.MatchLabels)
	require.Equal(t, int32(2), reader.podGets.Load())
}

func TestIstioLearningAggregationLateLookupCannotOverwriteCurrentMemo(t *testing.T) {
	for _, tc := range []struct {
		name          string
		advanceWindow bool
		wantPodGets   int32
	}{
		{name: "same generation", wantPodGets: 3},
		{name: "after rollover", advanceWindow: true, wantPodGets: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, oldOwner := newLearningObjects("server-0", "server", map[string]string{"app": "old"})
			reader := newLearningTestClient(t, pod, oldOwner)
			var learned []types.LearningEvent
			var learnedMu sync.Mutex
			scraper := newLearningTestScraper(reader, func(event types.LearningEvent) bool {
				learnedMu.Lock()
				defer learnedMu.Unlock()
				learned = append(learned, event)
				return true
			}, nil)
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			scraper.now = func() time.Time { return now }
			oldUID := oldOwner.UID
			oldRead := make(chan struct{})
			releaseOldRead := make(chan struct{})
			var blockOnce sync.Once
			reader.afterGet = func(object client.Object) {
				statefulSet, ok := object.(*appsv1.StatefulSet)
				if ok && statefulSet.UID == oldUID {
					blockOnce.Do(func() {
						close(oldRead)
						<-releaseOldRead
					})
				}
			}

			oldDone := make(chan struct{})
			go func() {
				scraper.processEvent(context.Background(), newLearningEvent("server-0", "old-client", "8080"))
				close(oldDone)
			}()
			<-oldRead

			if tc.advanceWindow {
				now = now.Add(learningAggregationWindow)
			}
			newPod, newOwner := newLearningObjects("server-0", "server", map[string]string{"app": "new"})
			newUID := k8stypes.UID("server-recreated-uid")
			newPod.OwnerReferences[0].UID = newUID
			newOwner.UID = newUID
			require.NoError(t, reader.Update(context.Background(), newPod))
			require.NoError(t, reader.Update(context.Background(), newOwner))
			scraper.processEvent(context.Background(), newLearningEvent("server-0", "new-client", "8080"))

			close(releaseOldRead)
			<-oldDone
			reader.afterGet = nil
			learnedMu.Lock()
			learnedCount := len(learned)
			learnedMu.Unlock()
			require.Equal(t, 2, learnedCount, "both resolved events are delivered")

			scraper.processEvent(context.Background(), newLearningEvent("server-0", "new-client", "8080"))
			require.Equal(
				t,
				tc.wantPodGets,
				reader.podGets.Load(),
				"old resolution must not replace the new generation's memo",
			)
		})
	}
}

func TestIstioLearningAggregationOversizedKeyBypassesRetention(t *testing.T) {
	pod, owner := newLearningObjects("server-0", "server", map[string]string{"app": "server"})
	reader := newLearningTestClient(t, pod, owner)
	var learned int
	scraper := newLearningTestScraper(reader, func(types.LearningEvent) bool {
		learned++
		return true
	}, nil)
	event := newLearningEvent("server-0", strings.Repeat("x", maxLearningAggregationKeyBytes), "8080")
	scraper.processEvent(context.Background(), event)
	scraper.processEvent(context.Background(), event)

	require.Equal(t, 2, learned)
	require.Equal(t, int32(2), reader.podGets.Load(), "oversized keys bypass retention without dropping learning")
}

func TestIstioLearningAggregationWindowDoesNotRewind(t *testing.T) {
	aggregation := newLearningAggregation()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pod := learningPodKey{namespace: "default", name: "server-0"}
	owner := learningWorkloadKey{
		namespace: "default",
		kind:      securityv1alpha1.WorkloadKindStatefulSet,
		name:      "server",
		uid:       "server-uid",
	}
	tuple := learningTupleKey{workload: owner, identity: "client", port: 8080}
	generation, _ := aggregation.beginResolution(func() time.Time { return start }, pod, "client", 8080)
	require.Equal(
		t,
		learningEnqueueAccepted,
		aggregation.enqueueResolved(
			func() time.Time { return start },
			generation,
			pod,
			tuple,
			func() bool { return true },
		),
	)

	newStart := start.Add(learningAggregationWindow)
	aggregation.mu.Lock()
	aggregation.rotate(newStart)
	newGeneration := aggregation.generation
	aggregation.pods[pod] = learningPodMemo{workload: owner}
	aggregation.accepted[tuple] = struct{}{}
	started := make(chan struct{})
	done := make(chan struct{})
	var observedGeneration uint64
	var suppressed bool
	go func() {
		close(started)
		observedGeneration, suppressed = aggregation.beginResolution(func() time.Time {
			return start.Add(learningAggregationWindow - time.Nanosecond)
		}, pod, "client", 8080)
		close(done)
	}()
	<-started
	aggregation.mu.Unlock()
	<-done

	require.Equal(t, newGeneration, observedGeneration)
	require.True(t, suppressed, "an older timestamp must not clear the current generation")
}

func TestIstioLearningAggregationRetriesLookupFailureAndUnsupportedPod(t *testing.T) {
	unsupported := &corev1.Pod{Namespace: "default", Name: "unsupported"}
	reader := newLearningTestClient(t, unsupported)
	var learned []types.LearningEvent
	scraper := newLearningTestScraper(reader, func(event types.LearningEvent) bool {
		learned = append(learned, event)
		return true
	}, nil)
	ctx := context.Background()

	unsupportedEvent := newLearningEvent("unsupported", "client", "8080")
	scraper.processEvent(ctx, unsupportedEvent)
	require.Empty(t, learned)
	pod, owner := newLearningObjects("unsupported", "supported", map[string]string{"app": "supported"})
	require.NoError(t, reader.Update(ctx, pod))
	require.NoError(t, reader.Create(ctx, owner))
	scraper.processEvent(ctx, unsupportedEvent)
	require.Len(t, learned, 1, "unsupported results are not memoized")

	missingEvent := newLearningEvent("later", "other-client", "8080")
	scraper.processEvent(ctx, missingEvent)
	later, _ := newLearningObjects("later", "supported", map[string]string{"app": "supported"})
	require.NoError(t, reader.Create(ctx, later))
	scraper.processEvent(ctx, missingEvent)
	require.Len(t, learned, 2, "lookup errors are retried instead of marked accepted")
	require.Equal(t, int32(4), reader.podGets.Load())
}

func TestIstioLearningAggregationConcurrentColdEventsEnqueueOnce(t *testing.T) {
	podA, owner := newLearningObjects("server-0", "server", map[string]string{"app": "server"})
	podB, _ := newLearningObjects("server-1", "server", map[string]string{"app": "server"})
	reader := newLearningTestClient(t, podA, podB, owner)
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	reader.beforePodGet = func() {
		entered <- struct{}{}
		<-release
	}
	var enqueued atomic.Int32
	scraper := newLearningTestScraper(reader, func(types.LearningEvent) bool {
		enqueued.Add(1)
		return true
	}, nil)
	events := []*agentv1.Event{
		newLearningEvent("server-0", "client", "8080"),
		newLearningEvent("server-0", "client", "8080"),
		newLearningEvent("server-1", "client", "8080"),
	}
	var workers sync.WaitGroup
	for _, event := range events {
		workers.Add(1)
		go func(event *agentv1.Event) {
			defer workers.Done()
			scraper.processEvent(context.Background(), event)
		}(event)
	}
	for range events {
		<-entered
	}
	close(release)
	workers.Wait()

	require.Equal(t, int32(3), reader.podGets.Load(), "cold calls may resolve concurrently")
	require.Equal(t, int32(1), enqueued.Load(), "tuple acceptance and enqueue are atomic")
}

func TestIstioLearningAggregationCancellationDoesNotMarkAccepted(t *testing.T) {
	pod, owner := newLearningObjects("server-0", "server", map[string]string{"app": "server"})
	reader := newLearningTestClient(t, pod, owner)
	var learned []types.LearningEvent
	scraper := newLearningTestScraper(reader, func(event types.LearningEvent) bool {
		learned = append(learned, event)
		return true
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	reader.afterGet = func(object client.Object) {
		if _, ok := object.(*appsv1.StatefulSet); ok {
			cancel()
		}
	}
	event := newLearningEvent("server-0", "client", "8080")
	scraper.processEvent(ctx, event)
	require.Empty(t, learned)

	reader.afterGet = nil
	scraper.processEvent(context.Background(), event)
	require.Len(t, learned, 1, "a cancelled resolution is not marked accepted")
	require.Equal(t, int32(2), reader.podGets.Load())
}

func TestIstioLearningAggregationQueueRejectionCanRetry(t *testing.T) {
	pod, owner := newLearningObjects("server-0", "server", map[string]string{"app": "server"})
	reader := newLearningTestClient(t, pod, owner)
	var attempts atomic.Int32
	scraper := newLearningTestScraper(reader, func(types.LearningEvent) bool {
		return attempts.Add(1) > 1
	}, nil)
	event := newLearningEvent("server-0", "client", "8080")
	scraper.processEvent(context.Background(), event)
	scraper.processEvent(context.Background(), event)
	require.Equal(t, int32(2), reader.podGets.Load(), "a rejected enqueue is not marked accepted")
	require.Equal(t, int32(2), attempts.Load())
	scraper.processEvent(context.Background(), event)
	require.Equal(t, int32(2), reader.podGets.Load(), "only the successful retry is suppressed")
}

func TestIstioLearningAggregationBoundedCachesRecoverAfterSaturation(t *testing.T) {
	aggregation := newLearningAggregation()
	now := time.Now()
	clock := func() time.Time { return now }
	generation, _ := aggregation.beginResolution(clock, learningPodKey{}, "first", 80)
	for i := range maxLearningAggregationEntries {
		pod := learningPodKey{namespace: "ns", name: fmt.Sprintf("pod-%d", i)}
		owner := learningWorkloadKey{namespace: "ns", kind: securityv1alpha1.WorkloadKindStatefulSet, name: "owner"}
		aggregation.pods[pod] = learningPodMemo{workload: owner}
		aggregation.accepted[learningTupleKey{workload: owner, identity: fmt.Sprintf("id-%d", i), port: 80}] = struct{}{}
	}

	newPod := learningPodKey{namespace: "ns", name: "new-pod"}
	newTuple := learningTupleKey{
		workload: learningWorkloadKey{namespace: "ns", kind: securityv1alpha1.WorkloadKindStatefulSet, name: "owner"},
		identity: "new-id", port: 80,
	}
	var enqueued bool
	result := aggregation.enqueueResolved(clock, generation, newPod, newTuple, func() bool {
		enqueued = true
		return true
	})
	require.Equal(t, learningEnqueueAccepted, result)
	require.True(t, enqueued, "saturation must not drop learning")
	require.Len(t, aggregation.pods, maxLearningAggregationEntries)
	require.Len(t, aggregation.accepted, maxLearningAggregationEntries)

	now = now.Add(learningAggregationWindow)
	newGeneration, suppressed := aggregation.beginResolution(clock, newPod, "new-id", 80)
	require.False(t, suppressed)
	require.NotEqual(t, generation, newGeneration)
	require.Empty(t, aggregation.pods)
	require.Empty(t, aggregation.accepted)
}

type learningBenchmarkScenario struct {
	name   string
	events []*agentv1.Event
}

func BenchmarkIstioLearningAggregation(b *testing.B) {
	for _, scenario := range learningBenchmarkScenarios() {
		for _, aggregated := range []bool{false, true} {
			name := "baseline"
			if aggregated {
				name = "aggregated"
			}
			b.Run(scenario.name+"/"+name, func(b *testing.B) {
				benchmarkIstioLearningPath(b, scenario.events, aggregated, false)
			})
		}
	}
	for _, aggregated := range []bool{false, true} {
		name := "baseline"
		if aggregated {
			name = "aggregated"
		}
		b.Run("two-puller/"+name, func(b *testing.B) {
			benchmarkIstioLearningPath(b, learningBenchmarkScenarios()[0].events, aggregated, true)
		})
	}
}

func learningBenchmarkScenarios() []learningBenchmarkScenario {
	const (
		eventCount = 100_000
		podCount   = 100
	)
	repeatedEvents := make([]*agentv1.Event, eventCount)
	mostlyUniqueEvents := make([]*agentv1.Event, eventCount)
	repeatedByPod := make([]*agentv1.Event, podCount)
	for i := range podCount {
		repeatedByPod[i] = newLearningEvent(fmt.Sprintf("server-%03d", i), "client", "8080")
	}
	for i := range eventCount {
		repeatedEvents[i] = repeatedByPod[i%podCount]
		identity := i
		if i%20 == 19 {
			identity--
		}
		pod := (i / 20) % podCount
		mostlyUniqueEvents[i] = newLearningEvent(
			fmt.Sprintf("server-%03d", pod),
			fmt.Sprintf("bench-client-%06d", identity),
			"8080",
		)
	}
	return []learningBenchmarkScenario{
		{name: "repeated", events: repeatedEvents},
		{name: "mostly-unique", events: mostlyUniqueEvents},
	}
}

func benchmarkIstioLearningPath(b *testing.B, events []*agentv1.Event, aggregated, twoPuller bool) {
	b.Helper()
	objects := make([]client.Object, 0, 101)
	for i := range 100 {
		pod, _ := newLearningObjects(fmt.Sprintf("server-%03d", i), "server", map[string]string{"app": "server"})
		objects = append(objects, pod)
	}
	_, owner := newLearningObjects("server-000", "server", map[string]string{"app": "server"})
	objects = append(objects, owner)
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		b.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		b.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	reader := &countingLearningClient{Client: base}
	var enqueued atomic.Int64
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var registerer prometheus.Registerer
	if aggregated {
		registerer = prometheus.NewRegistry()
	}
	scraper := newLearningTestScraper(reader, func(types.LearningEvent) bool {
		enqueued.Add(1)
		return true
	}, registerer)
	if !aggregated {
		scraper.learningAggregation = nil
	}
	scraper.now = func() time.Time { return now }
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	if twoPuller {
		var workers sync.WaitGroup
		for worker := range 2 {
			workers.Add(1)
			go func(worker int) {
				defer workers.Done()
				for i := worker; i < b.N; i += 2 {
					scraper.processEvent(ctx, events[i%len(events)])
				}
			}(worker)
		}
		workers.Wait()
	} else {
		for i := range b.N {
			scraper.processEvent(ctx, events[i%len(events)])
			now = now.Add(200 * time.Microsecond)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(reader.podGets.Load())/float64(b.N), "lookups/event")
	b.ReportMetric(float64(enqueued.Load())/float64(b.N), "enqueues/event")
	if aggregated {
		b.ReportMetric(testutil.ToFloat64(scraper.learningLookupsSuppressed)/float64(b.N), "suppressed/event")
	}
}
