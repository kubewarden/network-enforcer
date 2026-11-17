package scraper

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/network-enforcer/internal/grpcexporter"
)

type podInformerCache struct {
	cache.Cache

	informer toolscache.SharedIndexInformer
}

func (c podInformerCache) GetInformer(
	_ context.Context,
	_ client.Object,
	_ ...cache.InformerGetOption,
) (cache.Informer, error) {
	return c.informer, nil
}

func (c podInformerCache) WaitForCacheSync(ctx context.Context) bool {
	return toolscache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced)
}

type informerErrorCache struct {
	cache.Cache

	getErr     error
	waitCalled bool
}

func (c *informerErrorCache) GetInformer(
	context.Context,
	client.Object,
	...cache.InformerGetOption,
) (cache.Informer, error) {
	return nil, c.getErr
}

func (c *informerErrorCache) WaitForCacheSync(context.Context) bool {
	c.waitCalled = true
	return true
}

func TestIstioScraperInformerAcquisitionErrorReturnsBeforeStarting(t *testing.T) {
	wantErr := errors.New("cache unavailable")
	cacheStub := &informerErrorCache{getErr: wantErr}
	dialCalls := 0
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.ConfigurePulling(IstioPullConfig{
		Cache: cacheStub, Reader: k8sfake.NewClientBuilder().Build(),
		DialAgent: func(context.Context, string, string) (grpcexporter.AgentClientAPI, error) {
			dialCalls++
			return nil, errors.New("unexpected dial")
		},
		Namespace: "agents", LabelSelector: "component=agent", GRPCPort: 50052,
		PollInterval: time.Second, ScrapeTimeout: time.Second, MaxInFlight: 1,
	})

	err := scraper.Start(context.Background())
	require.ErrorIs(t, err, wantErr)
	require.ErrorContains(t, err, "get Pod informer for Istio agent discovery")
	require.False(t, cacheStub.waitCalled)
	require.Zero(t, dialCalls)
}

func TestIstioScraperConsumesRealPodInformerLifecycle(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	pod := func(name string, uid k8stypes.UID, namespace, component, ip string) *corev1.Pod {
		return &corev1.Pod{
			Name:      name,
			Namespace: namespace,
			UID:       uid,
			Labels: map[string]string{
				"app.kubernetes.io/component": component,
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip},
		}
	}
	initialA := pod("agent-a", "uid-a", "agents", "agent", "10.0.0.1")
	initialB := pod("agent-b", "uid-b", "agents", "agent", "10.0.0.2")
	ignored := pod("not-agent", "uid-x", "agents", "other", "10.0.0.9")
	reader := k8sfake.NewClientBuilder().WithScheme(scheme).WithObjects(initialA, initialB, ignored).Build()
	watcher := watch.NewFake()
	listWatch := &toolscache.ListWatch{
		ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
			return &corev1.PodList{
				Items: []corev1.Pod{*initialA.DeepCopy(), *initialB.DeepCopy(), *ignored.DeepCopy()},
			}, nil
		},
		WatchFuncWithContext: func(_ context.Context, options metav1.ListOptions) (watch.Interface, error) {
			if options.SendInitialEvents != nil && *options.SendInitialEvents {
				go sendInitialPodWatchEvents(watcher, initialA, initialB, ignored)
			}
			return watcher, nil
		},
	}
	informer := toolscache.NewSharedIndexInformer(listWatch, &corev1.Pod{}, 0, toolscache.Indexers{})
	informerCtx := t.Context()
	go informer.Run(informerCtx.Done())
	require.True(t, toolscache.WaitForCacheSync(informerCtx.Done(), informer.HasSynced))

	dials := make(chan string, 20)
	cancellations := make(chan string, 20)
	var activeMu sync.Mutex
	active := map[string]bool{}
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.ConfigurePulling(IstioPullConfig{
		Cache: podInformerCache{informer: informer}, Reader: reader,
		Namespace: "agents", LabelSelector: "app.kubernetes.io/component=agent", GRPCPort: 50052,
		PollInterval: time.Nanosecond, ScrapeTimeout: 10 * time.Second, MaxInFlight: 2,
		DialAgent: func(_ context.Context, _, authority string) (grpcexporter.AgentClientAPI, error) {
			dials <- authority
			activeMu.Lock()
			active[authority] = true
			activeMu.Unlock()
			return &blockingAgentClient{cancelled: cancellations, name: authority}, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	startDone := make(chan error, 1)
	go func() { startDone <- scraper.Start(ctx) }()

	dialed := map[string]bool{}
	for len(dialed) < 2 {
		select {
		case authority := <-dials:
			dialed[authority] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("initial informer delivery did not start both agent workers; started %v", dialed)
		}
	}
	require.Equal(t, map[string]bool{"agent-a.agents": true, "agent-b.agents": true}, dialed)
	select {
	case name := <-dials:
		t.Fatalf("unexpected nonmatching Pod started a worker: %s", name)
	case <-time.After(20 * time.Millisecond):
	}

	updatedA := initialA.DeepCopy()
	updatedA.Labels["app.kubernetes.io/component"] = "not-agent"
	require.NoError(t, reader.Update(context.Background(), updatedA))
	watcher.Modify(updatedA)
	require.Equal(t, "agent-a.agents", receiveString(t, cancellations))
	activeMu.Lock()
	require.True(t, active["agent-b.agents"], "retiring A must not cancel B")
	activeMu.Unlock()

	podC := pod("agent-c", "uid-c", "agents", "agent", "2001:db8::3")
	require.NoError(t, reader.Create(context.Background(), podC))
	watcher.Add(podC)
	require.Equal(t, "agent-c.agents", receiveString(t, dials))

	require.NoError(t, reader.Delete(context.Background(), podC))
	watcher.Delete(podC)
	require.Equal(t, "agent-c.agents", receiveString(t, cancellations))
	cancel()
	select {
	case err := <-startDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("scraper did not stop and join remaining agent workers")
	}
	require.Equal(t, "agent-b.agents", receiveString(t, cancellations))
}

func TestIstioScraperWithZeroAgentsRunsUntilCancellation(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	watcher := watch.NewFake()
	listWatch := &toolscache.ListWatch{
		ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
			return &corev1.PodList{}, nil
		},
		WatchFuncWithContext: func(_ context.Context, options metav1.ListOptions) (watch.Interface, error) {
			if options.SendInitialEvents != nil && *options.SendInitialEvents {
				go sendInitialPodWatchEvents(watcher)
			}
			return watcher, nil
		},
	}
	informer := toolscache.NewSharedIndexInformer(listWatch, &corev1.Pod{}, 0, toolscache.Indexers{})
	informerCtx := t.Context()
	go informer.Run(informerCtx.Done())
	require.True(t, toolscache.WaitForCacheSync(informerCtx.Done(), informer.HasSynced))
	reader := k8sfake.NewClientBuilder().WithScheme(scheme).Build()
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.ConfigurePulling(IstioPullConfig{
		Cache: podInformerCache{informer: informer}, Reader: reader,
		Namespace: "agents", LabelSelector: "component=agent", GRPCPort: 50052,
		PollInterval: time.Second, ScrapeTimeout: time.Second, MaxInFlight: 1,
		DialAgent: func(context.Context, string, string) (grpcexporter.AgentClientAPI, error) {
			return nil, errors.New("no agent Pods are expected")
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scraper.Start(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("zero-agent runnable stopped unexpectedly: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("zero-agent runnable did not shut down")
	}
}

func sendInitialPodWatchEvents(watcher *watch.FakeWatcher, pods ...*corev1.Pod) {
	for _, pod := range pods {
		watcher.Add(pod.DeepCopy())
	}
	watcher.Action(watch.Bookmark, &corev1.Pod{
		ResourceVersion: "1",
		Annotations:     map[string]string{"k8s.io/initial-events-end": "true"}})
}

func receiveString(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for agent lifecycle event")
		return ""
	}
}
