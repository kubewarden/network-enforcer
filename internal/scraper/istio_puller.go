package scraper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/network-enforcer/internal/grpcexporter"
)

const (
	// DefaultAgentLabelSelector selects agents in the default deployment identity.
	DefaultAgentLabelSelector = "app.kubernetes.io/name=network-enforcer,app.kubernetes.io/component=agent"
	// DefaultAgentGRPCPort is the agent's default gRPC listener port.
	DefaultAgentGRPCPort = 50052
	// DefaultAgentPollInterval is the successful poll delay before jitter.
	DefaultAgentPollInterval = 5 * time.Second
	// DefaultAgentScrapeTimeout bounds one scrape RPC.
	DefaultAgentScrapeTimeout = 30 * time.Second
	// DefaultAgentMaxInFlight bounds concurrent scrapes and event processing.
	DefaultAgentMaxInFlight = 2

	initialAgentRetryBackoff     = time.Second
	maximumAgentRetryBackoff     = 30 * time.Second
	agentPollJitterFraction      = 0.2
	initialAgentPollDelayDivisor = 2
	agentRetryBackoffFactor      = 2
)

// AgentDialFunc creates a new client for one poll. The authority is the expected Pod DNS identity.
type AgentDialFunc func(context.Context, string, string) (grpcexporter.AgentClientAPI, error)

// IstioPullConfig configures discovery and polling of the Istio agent Pods.
type IstioPullConfig struct {
	Cache         cache.Cache
	Reader        client.Reader
	DialAgent     AgentDialFunc
	Namespace     string
	LabelSelector string
	GRPCPort      int
	PollInterval  time.Duration
	ScrapeTimeout time.Duration
	MaxInFlight   int
}

type agentWorker struct {
	key       k8stypes.NamespacedName
	uid       k8stypes.UID
	ip        string
	endpoint  string
	authority string
	cancel    context.CancelFunc
	done      chan struct{}
}

// ConfigurePulling sets the discovery and polling dependencies.
func (s *IstioScraper) ConfigurePulling(conf IstioPullConfig) {
	s.pull = conf
}

func (s *IstioScraper) NeedLeaderElection() bool {
	return true
}

//nolint:funlen // Keep discovery and worker cleanup in the same lifecycle.
func (s *IstioScraper) Start(ctx context.Context) error {
	if s.pull.MaxInFlight <= 0 {
		return errors.New("--agent-max-in-flight must be positive")
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}

	informer, err := s.pull.Cache.GetInformer(ctx, &corev1.Pod{})
	if err != nil {
		return fmt.Errorf("get Pod informer for Istio agent discovery: %w", err)
	}
	queue := workqueue.NewTypedRateLimitingQueue[k8stypes.NamespacedName](
		workqueue.DefaultTypedControllerRateLimiter[k8stypes.NamespacedName](),
	)
	registration, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) { enqueueAgentPod(queue, obj) },
		UpdateFunc: func(_, newObj any) {
			enqueueAgentPod(queue, newObj)
		},
		DeleteFunc: func(obj any) { enqueueAgentPod(queue, obj) },
	})
	if err != nil {
		queue.ShutDown()
		return fmt.Errorf("register Pod informer handler for Istio agent discovery: %w", err)
	}

	stopped := make(chan struct{})
	shutdownWatcherDone := make(chan struct{})
	go func() {
		defer close(shutdownWatcherDone)
		select {
		case <-ctx.Done():
			queue.ShutDown()
		case <-stopped:
		}
	}()

	workers := make(map[k8stypes.NamespacedName]*agentWorker)
	defer func() {
		close(stopped)
		_ = informer.RemoveEventHandler(registration)
		queue.ShutDown()
		for key, worker := range workers {
			s.retireWorker(key, worker)
		}
		<-shutdownWatcherDone
	}()

	s.Logger.InfoContext(ctx, "Watching Pods for Istio agents",
		"namespace", s.pull.Namespace,
		"labelSelector", s.pull.LabelSelector,
		"grpcPort", s.pull.GRPCPort,
		"pollInterval", s.pull.PollInterval,
		"maxInFlight", s.pull.MaxInFlight,
	)
	if !s.pull.Cache.WaitForCacheSync(ctx) {
		return nil
	}
	if !toolscache.WaitForCacheSync(ctx.Done(), registration.HasSynced) {
		return nil
	}

	permits := make(chan struct{}, s.pull.MaxInFlight)
	for {
		key, shutdown := queue.Get()
		if shutdown {
			return nil
		}
		if ctx.Err() != nil {
			queue.Done(key)
			queue.Forget(key)
			continue
		}
		reconcileErr := s.reconcileAgentPod(ctx, key, workers, permits)
		queue.Done(key)
		if reconcileErr != nil {
			if apierrors.IsNotFound(reconcileErr) {
				queue.Forget(key)
				continue
			}
			s.Logger.WarnContext(ctx, "Failed to reconcile Istio agent Pod, retrying",
				"pod", key.String(), "error", reconcileErr)
			queue.AddRateLimited(key)
			continue
		}
		queue.Forget(key)
	}
}

func enqueueAgentPod(queue workqueue.TypedRateLimitingInterface[k8stypes.NamespacedName], obj any) {
	key, err := toolscache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	namespace, name, found := strings.Cut(key, "/")
	if !found || namespace == "" || name == "" {
		return
	}
	queue.Add(k8stypes.NamespacedName{Namespace: namespace, Name: name})
}

func (s *IstioScraper) reconcileAgentPod(
	ctx context.Context,
	key k8stypes.NamespacedName,
	workers map[k8stypes.NamespacedName]*agentWorker,
	permits chan struct{},
) error {
	pod := &corev1.Pod{}
	if err := s.pull.Reader.Get(ctx, key, pod); err != nil {
		if apierrors.IsNotFound(err) {
			s.retireWorker(key, workers[key])
			delete(workers, key)
		}
		return err
	}

	selector, err := labels.Parse(s.pull.LabelSelector)
	if err != nil {
		return err
	}
	eligible := pod.Namespace == s.pull.Namespace &&
		selector.Matches(labels.Set(pod.Labels)) &&
		pod.Status.Phase == corev1.PodRunning &&
		pod.DeletionTimestamp == nil &&
		pod.Status.PodIP != ""
	if !eligible {
		if worker := workers[key]; worker != nil {
			s.retireWorker(key, worker)
			delete(workers, key)
		}
		return nil
	}

	port := strconv.Itoa(s.pull.GRPCPort)
	endpoint := net.JoinHostPort(pod.Status.PodIP, port)
	authority := pod.Name + "." + pod.Namespace
	if worker := workers[key]; worker != nil {
		// Eligibility is checked first so label/phase/termination changes are
		// honored even when the Pod UID and endpoint are unchanged.
		if worker.uid == pod.UID && worker.endpoint == endpoint && worker.authority == authority {
			return nil
		}
		s.retireWorker(key, worker)
		delete(workers, key)
	}

	workerCtx, cancel := context.WithCancel(ctx)
	worker := &agentWorker{
		key: key, uid: pod.UID, ip: pod.Status.PodIP,
		endpoint: endpoint, authority: authority, cancel: cancel, done: make(chan struct{}),
	}
	workers[key] = worker
	s.Logger.InfoContext(ctx, "Discovered Istio agent Pod",
		"pod", key.String(), "uid", pod.UID, "endpoint", endpoint, "authority", authority)
	go s.runAgent(workerCtx, worker, permits)
	return nil
}

func (s *IstioScraper) retireWorker(key k8stypes.NamespacedName, worker *agentWorker) {
	if worker == nil {
		return
	}
	s.Logger.Info("Retiring Istio agent Pod worker", "pod", key.String(), "uid", worker.uid)
	worker.cancel()
	<-worker.done
}

func (s *IstioScraper) runAgent(ctx context.Context, worker *agentWorker, permits chan struct{}) {
	defer close(worker.done)
	initialBackoff := wait.Backoff{
		Duration: initialAgentRetryBackoff,
		Factor:   agentRetryBackoffFactor,
		Steps:    math.MaxInt,
		Cap:      maximumAgentRetryBackoff,
	}
	backoff := initialBackoff
	failures := 0
	delay := s.jitter(s.pull.PollInterval/initialAgentPollDelayDivisor, 1)
	for {
		if !s.wait(ctx, delay) {
			return
		}
		select {
		case permits <- struct{}{}:
		case <-ctx.Done():
			return
		}
		if ctx.Err() != nil {
			<-permits
			return
		}

		err := s.scrapeOnce(ctx, worker)
		<-permits
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			delay = min(s.jitter(backoff.Step(), agentPollJitterFraction), maximumAgentRetryBackoff)
			s.Logger.WarnContext(ctx, "Istio agent poll failed, retrying",
				"pod", worker.key.String(), "endpoint", worker.endpoint,
				"failures", failures, "retryAfter", delay, "error", err)
			continue
		}
		failures = 0
		backoff = initialBackoff
		delay = s.jitter(s.pull.PollInterval, agentPollJitterFraction)
	}
}

func (s *IstioScraper) scrapeOnce(ctx context.Context, worker *agentWorker) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, err := s.pull.DialAgent(ctx, worker.endpoint, worker.authority)
	if err != nil {
		return fmt.Errorf("dial agent: %w", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			s.Logger.WarnContext(ctx, "Failed to close Istio agent client",
				"pod", worker.key.String(), "error", closeErr)
		}
	}()

	pollCtx, cancel := context.WithTimeout(ctx, s.pull.ScrapeTimeout)
	events, err := client.ScrapeEvents(pollCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("scrape events: %w", err)
	}
	for _, event := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.processEvent(ctx, event)
	}
	return nil
}

func waitForDelay(ctx context.Context, delay time.Duration) bool {
	return wait.PollUntilContextCancel(ctx, delay, false, func(context.Context) (bool, error) {
		return true, nil
	}) == nil
}
