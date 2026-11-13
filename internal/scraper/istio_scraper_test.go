package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/kubewarden/network-enforcer/api/v1alpha1"
	"github.com/kubewarden/network-enforcer/internal/agentbuffer"
	"github.com/kubewarden/network-enforcer/internal/grpcexporter"
	"github.com/kubewarden/network-enforcer/internal/istio"
	"github.com/kubewarden/network-enforcer/internal/ringbuf"
	"github.com/kubewarden/network-enforcer/internal/types"
	"github.com/kubewarden/network-enforcer/internal/violation"
	"github.com/kubewarden/network-enforcer/internal/workload"
	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

type fakeOtelEventLogger struct {
	embedded.Logger

	emitted []otellog.Record
}

func (f *fakeOtelEventLogger) Enabled(context.Context, otellog.EnabledParameters) bool { return true }
func (f *fakeOtelEventLogger) Emit(_ context.Context, rec otellog.Record) {
	f.emitted = append(f.emitted, rec.Clone())
}

func deploymentTarget(name string) securityv1alpha1.WorkloadTargetRef {
	return securityv1alpha1.WorkloadTargetRef{Kind: securityv1alpha1.WorkloadKindDeployment, Name: name}
}

func typedPolicy(mode agentv1.PolicyMode, timestamp *timestamppb.Timestamp, raw []byte) *agentv1.Event {
	return &agentv1.Event{
		ObservedAt: timestamp,
		RawRecord:  raw,
		Kind: &agentv1.Event_Policy{Policy: &agentv1.PolicyEvent{
			Mode: mode, DestinationNamespacedName: "default/server-pod",
			Policy: "default/allow-server", SourceAddress: "10.0.0.5:4567",
		}},
	}
}

func TestProcessTypedPolicyEventsPreservesModeAndDoesNotDeduplicate(t *testing.T) {
	t.Parallel()
	buffer := ringbuf.New[violation.Observation]()
	otelLogger := &fakeOtelEventLogger{}
	scraper := NewIstioScraper(IstioScraperConfig{
		Logger: slog.New(slog.DiscardHandler), ViolationBuffer: buffer, ViolationOtelLogger: otelLogger,
	})
	oldTimestamp := timestamppb.New(time.Now().Add(-24 * time.Hour))
	monitor := typedPolicy(
		agentv1.PolicyMode_POLICY_MODE_MONITOR,
		oldTimestamp,
		[]byte(`{"message":"dry-run: deny policy match"}`),
	)
	protect := typedPolicy(
		agentv1.PolicyMode_POLICY_MODE_PROTECT,
		oldTimestamp,
		[]byte(`{"message":"deny policy match"}`),
	)
	scraper.processEvent(context.Background(), monitor)
	scraper.processEvent(context.Background(), monitor)
	scraper.processEvent(context.Background(), protect)

	observations := buffer.Drain()
	require.Len(t, observations, 3, "identical observations must not be deduplicated")
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeProtect, observations[0].Action)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, observations[1].Action)
	require.Equal(t, securityv1alpha1.WorkloadNetworkPolicyModeMonitor, observations[2].Action)
	require.Equal(t, oldTimestamp.AsTime(), observations[0].Timestamp.Time)
	require.Equal(t, "default", observations[0].Dest.Namespace)
	require.Equal(t, "server-pod", observations[0].Dest.OwnerName)
	require.Equal(t, "allow-server", observations[0].DenyingPolicyName)
	require.Len(t, otelLogger.emitted, 3)
}

func TestProcessTypedEventsLearningAndInvalidPayloads(t *testing.T) {
	t.Parallel()
	const podHash = "hash123"
	destination := &corev1.Pod{
		Name: "server-" + podHash + "-abc", Namespace: "default", Labels: map[string]string{
			appsv1.DefaultDeploymentUniqueLabelKey: podHash, "app": "server",
		}, OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "ReplicaSet",
				Name:       "server-" + podHash,
				Controller: new(true),
			},
		},
	}
	deployment := &appsv1.Deployment{Name: "server", Namespace: "default", Spec: appsv1.DeploymentSpec{
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
	}}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(destination, deployment).Build()

	var learned []types.LearningEvent
	scraper := NewIstioScraper(IstioScraperConfig{
		Logger: slog.New(slog.DiscardHandler), Enricher: istio.NewEnricher(cl),
		EnqueueLearningEvent: func(event types.LearningEvent) bool { learned = append(learned, event); return true },
	})
	name, namespace := destination.Name, destination.Namespace
	valid := &agentv1.Event{Kind: &agentv1.Event_Learn{Learn: &agentv1.LearnEvent{
		SourceIdentity: "spiffe://cluster.local/ns/default/sa/client", DestinationName: &name,
		DestinationNamespace: &namespace, DestinationPort: "8080",
	}}}
	scraper.processEvent(context.Background(), valid)
	require.Len(t, learned, 1)
	require.Equal(t, "cluster.local/ns/default/sa/client", learned[0].Source.Identity)
	require.Equal(t, "server", learned[0].Dest.OwnerName)
	require.Equal(t, int32(8080), learned[0].DstPort)
	require.Equal(t, corev1.ProtocolTCP, learned[0].Protocol)

	invalidPort := &agentv1.Event{Kind: &agentv1.Event_Learn{Learn: &agentv1.LearnEvent{
		SourceIdentity: "spiffe://client", DestinationName: &name,
		DestinationNamespace: &namespace, DestinationPort: "70000",
	}}}
	missingDestination := &agentv1.Event{Kind: &agentv1.Event_Learn{Learn: &agentv1.LearnEvent{
		SourceIdentity: "spiffe://client", DestinationPort: "80",
	}}}
	unknownMode := typedPolicy(agentv1.PolicyMode(77), nil, nil)
	noKind := &agentv1.Event{}
	for _, event := range []*agentv1.Event{invalidPort, missingDestination, unknownMode, noKind, nil} {
		scraper.processEvent(context.Background(), event)
	}
	require.Len(t, learned, 1)
}

func TestProcessTypedPolicyTimestampAndRawJSON(t *testing.T) {
	t.Parallel()
	flowBuffer := ringbuf.New[json.RawMessage]()
	violationBuffer := ringbuf.New[violation.Observation]()
	scraper := NewIstioScraper(IstioScraperConfig{
		Logger: slog.New(slog.DiscardHandler), FlowDumperBuffer: flowBuffer, ViolationBuffer: violationBuffer,
	})
	before := time.Now()
	scraper.processEvent(
		context.Background(),
		typedPolicy(agentv1.PolicyMode_POLICY_MODE_PROTECT, nil, []byte(`{"a":1}`)),
	)
	missingTimestamp := violationBuffer.Drain()[0].Timestamp.Time
	require.False(t, missingTimestamp.Before(before))
	require.JSONEq(t, `{"a":1}`, string(flowBuffer.Drain()[0]))

	epoch := timestamppb.New(time.Unix(0, 0))
	scraper.processEvent(
		context.Background(),
		typedPolicy(agentv1.PolicyMode_POLICY_MODE_PROTECT, epoch, []byte(`not json`)),
	)
	observation := violationBuffer.Drain()[0]
	require.Equal(t, time.Unix(0, 0).UTC(), observation.Timestamp.Time.UTC())
	require.Empty(t, flowBuffer.Drain(), "invalid debug JSON must not suppress policy processing")

	invalidTimestamp := &timestamppb.Timestamp{Seconds: 1 << 62}
	scraper.processEvent(
		context.Background(),
		typedPolicy(agentv1.PolicyMode_POLICY_MODE_PROTECT, invalidTimestamp, nil),
	)
	fallback := violationBuffer.Drain()[0].Timestamp.Time
	require.True(t, fallback.After(before))
}

func TestValidateIstioPullOptions(t *testing.T) {
	t.Parallel()
	valid := func() error {
		return ValidateIstioPullOptions(
			"agents",
			"app.kubernetes.io/component=agent",
			50052,
			5*time.Second,
			30*time.Second,
			2,
		)
	}
	require.NoError(t, valid())
	cases := []struct {
		name     string
		edit     func(*string, *string, *int, *time.Duration, *time.Duration, *int)
		contains string
	}{
		{
			"namespace required",
			func(ns, _ *string, _ *int, _ *time.Duration, _ *time.Duration, _ *int) { *ns = "" },
			"--agent-namespace",
		},
		{
			"selector required",
			func(_, sel *string, _ *int, _ *time.Duration, _ *time.Duration, _ *int) { *sel = "" },
			"--agent-label-selector",
		},
		{
			"selector valid",
			func(_, sel *string, _ *int, _ *time.Duration, _ *time.Duration, _ *int) { *sel = "not a selector" },
			"invalid --agent-label-selector",
		},
		{
			"port valid",
			func(_, _ *string, port *int, _ *time.Duration, _ *time.Duration, _ *int) { *port = 65536 },
			"--agent-grpc-port",
		},
		{
			"poll interval positive",
			func(_, _ *string, _ *int, interval *time.Duration, _ *time.Duration, _ *int) { *interval = 0 },
			"--agent-poll-interval",
		},
		{
			"timeout positive",
			func(_, _ *string, _ *int, _ *time.Duration, timeout *time.Duration, _ *int) { *timeout = 0 },
			"--agent-scrape-timeout",
		},
		{
			"in-flight positive",
			func(_, _ *string, _ *int, _ *time.Duration, _ *time.Duration, limit *int) { *limit = 0 },
			"--agent-max-in-flight",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ns, selector := "agents", "app.kubernetes.io/component=agent"
			port, interval, timeout, inFlight := 50052, 5*time.Second, 30*time.Second, 2
			tc.edit(&ns, &selector, &port, &interval, &timeout, &inFlight)
			err := ValidateIstioPullOptions(ns, selector, port, interval, timeout, inFlight)
			require.ErrorContains(t, err, tc.contains)
		})
	}
}

func TestIstioScraperRequiresLeaderElection(t *testing.T) {
	t.Parallel()
	require.True(t, NewIstioScraper(IstioScraperConfig{}).NeedLeaderElection())
}

func TestProcessPolicyEventEnrichesAttributionAndPreservesReportedPolicy(t *testing.T) {
	t.Parallel()
	const podHash = "abc123"
	destinationName := "server-" + podHash + "-pod"
	source := &corev1.Pod{
		Name: "client-pod", Namespace: "default",
		Spec:   corev1.PodSpec{ServiceAccountName: "client-sa"},
		Status: corev1.PodStatus{PodIP: "10.0.0.5"},
	}
	destination := &corev1.Pod{
		Name: destinationName, Namespace: "default", Labels: map[string]string{
			appsv1.DefaultDeploymentUniqueLabelKey: podHash, "app": "server",
		}, OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "ReplicaSet",
				Name:       "server-" + podHash,
				Controller: new(true),
			},
		},
		Spec: corev1.PodSpec{ServiceAccountName: "server-sa"},
	}
	policy := func(name, target string) *securityv1alpha1.WorkloadNetworkPolicy {
		return &securityv1alpha1.WorkloadNetworkPolicy{
			Name: name, Namespace: "default",
			Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
				PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
					Backend: securityv1alpha1.PolicyBackendIstio,
					Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
						Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					},
				},
				WorkloadTargetingSpec: securityv1alpha1.WorkloadTargetingSpec{
					TargetRef: deploymentTarget(target), Direction: networkingv1.PolicyTypeIngress,
				},
			},
		}
	}
	serverWNP, otherWNP := policy("allow-server", "server"), policy("allow-other", "other")
	authorizationPolicy := func(wnp *securityv1alpha1.WorkloadNetworkPolicy) *istiosecurityv1.AuthorizationPolicy {
		return &istiosecurityv1.AuthorizationPolicy{
			Name: wnp.Name, Namespace: wnp.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(
				wnp, securityv1alpha1.GroupVersion.WithKind(securityv1alpha1.WorkloadNetworkPolicyKind))},
		}
	}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	require.NoError(t, networkingv1.AddToScheme(scheme))
	require.NoError(t, securityv1alpha1.AddToScheme(scheme))
	require.NoError(t, istiosecurityv1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&corev1.Pod{}, istio.PodIPIndexField, istio.IndexPodByIP).
		WithIndex(&securityv1alpha1.WorkloadNetworkPolicy{}, workload.WNPTargetIndexField, workload.IndexWNPByTarget).
		WithStatusSubresource(&securityv1alpha1.WorkloadNetworkPolicy{}).
		WithObjects(source, destination, serverWNP, otherWNP, authorizationPolicy(serverWNP), authorizationPolicy(otherWNP)).
		Build()
	buffer := ringbuf.New[violation.Observation]()
	scraper := NewIstioScraper(IstioScraperConfig{
		Logger: slog.New(slog.DiscardHandler), Enricher: istio.NewEnricher(cl), ViolationBuffer: buffer,
	})
	event := &agentv1.Event{Kind: &agentv1.Event_Policy{Policy: &agentv1.PolicyEvent{
		Mode:                      agentv1.PolicyMode_POLICY_MODE_PROTECT,
		DestinationNamespacedName: "default/" + destinationName,
		Policy:                    "default/allow-other", SourceAddress: "10.0.0.5:4567",
	}}}
	scraper.processEvent(context.Background(), event)
	observation := buffer.Drain()[0]
	require.Equal(t, securityv1alpha1.WorkloadRef{
		Namespace: "default", OwnerKind: securityv1alpha1.WorkloadKindPod, OwnerName: "client-pod",
		Identity: "cluster.local/ns/default/sa/client-sa",
	}, observation.Source)
	require.Equal(t, securityv1alpha1.WorkloadRef{
		Namespace: "default", OwnerKind: securityv1alpha1.WorkloadKindDeployment, OwnerName: "server",
		Identity: "cluster.local/ns/default/sa/server-sa",
	}, observation.Dest)
	require.Equal(t, "allow-other", observation.DenyingPolicyName,
		"the reported policy is retained for controller disagreement accounting")

	buffer.Record(observation)
	registry := startStatusSync(t, cl, buffer)
	serverKey := k8stypes.NamespacedName{Namespace: "default", Name: serverWNP.Name}
	require.Eventually(t, func() bool {
		var stored securityv1alpha1.WorkloadNetworkPolicy
		if cl.Get(context.Background(), serverKey, &stored) != nil || len(stored.Status.Violations) != 1 {
			return false
		}
		return stored.Status.Violations[0].DenyingPolicyName == serverWNP.Name &&
			gatheredCounter(registry, disagreementMetric, map[string]string{"provider": "istio"}) == 1
	}, 5*time.Second, 20*time.Millisecond)
	var otherStored securityv1alpha1.WorkloadNetworkPolicy
	require.NoError(t, cl.Get(context.Background(), otherWNP.NamespacedName(), &otherStored))
	require.Empty(t, otherStored.Status.Violations)
}

type delayedContextReader struct {
	client.Client

	contextSeen chan context.Context
	release     chan struct{}
}

func (r delayedContextReader) List(ctx context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	r.contextSeen <- ctx
	<-r.release
	return nil
}

func TestScrapeTimeoutDoesNotCancelProcessingOfDrainedEvents(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	contextSeen := make(chan context.Context, 1)
	release := make(chan struct{})
	reader := delayedContextReader{Client: base, contextSeen: contextSeen, release: release}
	buffer := ringbuf.New[violation.Observation]()
	scraper := NewIstioScraper(IstioScraperConfig{
		Logger: slog.New(slog.DiscardHandler), Enricher: istio.NewEnricher(reader), ViolationBuffer: buffer,
	})
	scraper.pull = IstioPullConfig{
		ScrapeTimeout: 20 * time.Millisecond,
		DialAgent: func(context.Context, string, string) (grpcexporter.AgentClientAPI, error) {
			return &scriptedAgentClient{scrape: func(context.Context) ([]*agentv1.Event, error) {
				return []*agentv1.Event{typedPolicy(agentv1.PolicyMode_POLICY_MODE_PROTECT, nil, nil)}, nil
			}}, nil
		},
	}
	worker := &agentWorker{
		key:      k8stypes.NamespacedName{Namespace: "agents", Name: "agent"},
		endpoint: "10.0.0.1:50052", authority: "agent.agents",
	}
	done := make(chan error, 1)
	go func() { done <- scraper.scrapeOnce(context.Background(), worker) }()
	var processingCtx context.Context
	select {
	case processingCtx = <-contextSeen:
	case <-time.After(time.Second):
		t.Fatal("event processing did not reach enrichment")
	}
	time.Sleep(3 * scraper.pull.ScrapeTimeout)
	require.NoError(t, processingCtx.Err(), "the RPC timeout must not cancel processing after the response was drained")
	_, hasDeadline := processingCtx.Deadline()
	require.False(t, hasDeadline, "processing uses the worker lifecycle context, not the RPC deadline")
	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("event processing did not finish")
	}
	require.Len(t, buffer.Drain(), 1)
}

func TestAgentBufferRecordLineToGRPCToIstioScraper(t *testing.T) {
	t.Parallel()
	const podHash = "hash123"
	destination := &corev1.Pod{
		Name: "server-" + podHash + "-abc", Namespace: "default", Labels: map[string]string{
			appsv1.DefaultDeploymentUniqueLabelKey: podHash, "app": "server",
		}, OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: appsv1.SchemeGroupVersion.String(),
				Kind:       "ReplicaSet",
				Name:       "server-" + podHash,
				Controller: new(true),
			},
		},
	}
	deployment := &appsv1.Deployment{Name: "server", Namespace: "default", Spec: appsv1.DeploymentSpec{
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
	}}
	objsScheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(objsScheme))
	require.NoError(t, appsv1.AddToScheme(objsScheme))
	cl := fake.NewClientBuilder().WithScheme(objsScheme).WithObjects(destination, deployment).Build()

	buffer := agentbuffer.New()
	lines := []string{
		`2026-03-05T12:00:00Z stdout F {"message":"connection complete","direction":"inbound","src.identity":"spiffe://cluster.local/ns/default/sa/client","dst.identity":"spiffe://cluster.local/ns/default/sa/server","dst.workload":"` + destination.Name + `","dst.namespace":"default","dst.hbone_addr":"10.0.0.2:8080"}`,
		`2026-03-05T12:00:01Z stdout F {"message":"dry-run: deny policy match","proxy":{"wl":"default/` + destination.Name + `"},"policy":"default/monitor-policy","inbound":{"peer":"10.0.0.5:4567"}}`,
		`2026-03-05T12:00:02Z stdout F {"message":"deny policy match","proxy":{"wl":"default/` + destination.Name + `"},"policy":"default/protect-policy","inbound":{"peer":"10.0.0.5:4567"}}`,
	}
	for _, line := range lines {
		buffer.RecordLine([]byte(line))
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentServiceServer(server, buffer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()
	response, err := agentv1.NewAgentServiceClient(conn).ScrapeEvents(ctx, &agentv1.ScrapeEventsRequest{})
	require.NoError(t, err)

	var learned []types.LearningEvent
	flowBuffer := ringbuf.New[json.RawMessage]()
	violations := ringbuf.New[violation.Observation]()
	scraper := NewIstioScraper(IstioScraperConfig{
		Logger: slog.New(slog.DiscardHandler), Enricher: istio.NewEnricher(cl),
		EnqueueLearningEvent: func(event types.LearningEvent) bool { learned = append(learned, event); return true },
		ViolationBuffer:      violations, FlowDumperBuffer: flowBuffer,
	})
	for _, event := range response.GetEvents() {
		scraper.processEvent(ctx, event)
	}
	require.Len(t, learned, 1)
	require.Equal(t, "cluster.local/ns/default/sa/client", learned[0].Source.Identity)
	observations := violations.Drain()
	require.Len(t, observations, 2)
	require.ElementsMatch(t, []securityv1alpha1.WorkloadNetworkPolicyMode{
		securityv1alpha1.WorkloadNetworkPolicyModeProtect,
		securityv1alpha1.WorkloadNetworkPolicyModeMonitor,
	}, []securityv1alpha1.WorkloadNetworkPolicyMode{observations[0].Action, observations[1].Action})
	require.Len(t, flowBuffer.Drain(), 3)
}

func TestReconcileAgentPodEligibilityAndEndpointReplacement(t *testing.T) {
	t.Parallel()
	pod := &corev1.Pod{
		Name:      "agent-a",
		Namespace: "agents",
		UID:       "uid-a",
		Labels:    map[string]string{"component": "agent"},
		Status:    corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "2001:db8::1"},
	}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	calls := make(chan [2]string, 10)
	cancelled := make(chan string, 10)
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.ConfigurePulling(IstioPullConfig{
		Reader: cl,
		DialAgent: func(_ context.Context, endpoint, authority string) (grpcexporter.AgentClientAPI, error) {
			calls <- [2]string{endpoint, authority}
			return &blockingAgentClient{cancelled: cancelled, name: authority}, nil
		},
		Namespace:     "agents",
		LabelSelector: "component=agent",
		GRPCPort:      50052,
		PollInterval:  time.Nanosecond,
		ScrapeTimeout: time.Second,
		MaxInFlight:   1,
	})
	workers := make(map[k8stypes.NamespacedName]*agentWorker)
	key := k8stypes.NamespacedName{Namespace: "agents", Name: "agent-a"}
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), key, workers, make(chan struct{}, 1)))
	first := <-calls
	require.Equal(t, "[2001:db8::1]:50052", first[0])
	require.Equal(t, "agent-a.agents", first[1])
	updated := &corev1.Pod{}
	require.NoError(t, cl.Get(context.Background(), key, updated))
	updated.Labels = map[string]string{"component": "other"}
	require.NoError(t, cl.Update(context.Background(), updated))
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), key, workers, make(chan struct{}, 1)))
	require.Empty(t, workers)
	require.Eventually(t, func() bool { return len(cancelled) > 0 }, time.Second, 5*time.Millisecond)
}

func TestRetiringAgentPodLeavesOtherWorkersAndLaterAgentsRunning(t *testing.T) {
	t.Parallel()
	pod := func(name string, uid k8stypes.UID, ip string) *corev1.Pod {
		return &corev1.Pod{
			Name:      name,
			Namespace: "agents",
			UID:       uid,
			Labels:    map[string]string{"component": "agent"},
			Status:    corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip},
		}
	}
	keyA := k8stypes.NamespacedName{Namespace: "agents", Name: "agent-a"}
	keyB := k8stypes.NamespacedName{Namespace: "agents", Name: "agent-b"}
	reader := podMapReader{keyA: pod("agent-a", "uid-a", "10.0.0.1"), keyB: pod("agent-b", "uid-b", "10.0.0.2")}
	calls := make(chan [2]string, 20)
	cancelled := make(chan string, 20)
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.ConfigurePulling(IstioPullConfig{
		Reader: reader,
		DialAgent: func(_ context.Context, endpoint, authority string) (grpcexporter.AgentClientAPI, error) {
			calls <- [2]string{endpoint, authority}
			return &blockingAgentClient{cancelled: cancelled, name: authority}, nil
		},
		Namespace:     "agents",
		LabelSelector: "component=agent",
		GRPCPort:      50052,
		PollInterval:  time.Nanosecond,
		ScrapeTimeout: time.Hour,
		MaxInFlight:   2,
	})
	workers := make(map[k8stypes.NamespacedName]*agentWorker)
	permits := make(chan struct{}, 2)
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), keyA, workers, permits))
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), keyB, workers, permits))
	initialCalls := map[string]bool{}
	for range 2 {
		initialCalls[(<-calls)[1]] = true
	}
	require.Contains(t, initialCalls, "agent-a.agents")
	require.Contains(t, initialCalls, "agent-b.agents")
	require.Len(t, workers, 2)

	reader[keyA].Status.PodIP = "10.0.0.3"
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), keyA, workers, permits))
	require.Equal(t, "agent-a.agents", <-cancelled, "endpoint replacement joins only the old Pod worker")
	newA := <-calls
	require.Equal(t, "10.0.0.3:50052", newA[0])

	reader[keyA].UID = "uid-a-replacement"
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), keyA, workers, permits))
	require.Equal(t, "agent-a.agents", <-cancelled)
	<-calls
	require.Equal(t, k8stypes.UID("uid-a-replacement"), workers[keyA].uid)

	now := metav1.Now()
	reader[keyA].DeletionTimestamp = &now
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), keyA, workers, permits))
	require.Equal(t, "agent-a.agents", <-cancelled)
	require.NotNil(t, workers[keyB])

	keyC := k8stypes.NamespacedName{Namespace: "agents", Name: "agent-c"}
	reader[keyC] = pod("agent-c", "uid-c", "10.0.0.4")
	require.NoError(t, scraper.reconcileAgentPod(context.Background(), keyC, workers, permits))
	newC := <-calls
	require.Equal(t, "agent-c.agents", newC[1])
	require.NotNil(t, workers[keyB])
	require.NotNil(t, workers[keyC])
	delete(reader, keyC)
	err := scraper.reconcileAgentPod(context.Background(), keyC, workers, permits)
	require.True(t, apierrors.IsNotFound(err))
	require.Equal(t, "agent-c.agents", <-cancelled)

	for key, worker := range workers {
		scraper.retireWorker(key, worker)
	}
}

type podMapReader map[k8stypes.NamespacedName]*corev1.Pod

func (r podMapReader) Get(
	_ context.Context,
	key k8stypes.NamespacedName,
	obj client.Object,
	_ ...client.GetOption,
) error {
	pod, found := r[key]
	if !found {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, key.Name)
	}
	target, ok := obj.(*corev1.Pod)
	if !ok {
		return errors.New("pod map reader only supports Pod objects")
	}
	*target = *pod.DeepCopy()
	return nil
}

func (podMapReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("Pod map reader does not support List")
}

type blockingAgentClient struct {
	cancelled chan string
	name      string
}

func (c *blockingAgentClient) ScrapeEvents(ctx context.Context) ([]*agentv1.Event, error) {
	<-ctx.Done()
	if c.cancelled != nil {
		c.cancelled <- c.name
	}
	return nil, ctx.Err()
}
func (*blockingAgentClient) GetStatus(context.Context) (*agentv1.GetStatusResponse, error) {
	return &agentv1.GetStatusResponse{}, nil
}
func (*blockingAgentClient) Close() error { return nil }

func TestAgentAddressUsesJoinHostPort(t *testing.T) {
	t.Parallel()
	require.Equal(t, "[2001:db8::1]:50052", net.JoinHostPort("2001:db8::1", "50052"))
}

type scriptedAgentClient struct {
	scrape func(context.Context) ([]*agentv1.Event, error)
	closed *atomic.Int32
}

func (c *scriptedAgentClient) ScrapeEvents(ctx context.Context) ([]*agentv1.Event, error) {
	return c.scrape(ctx)
}
func (*scriptedAgentClient) GetStatus(context.Context) (*agentv1.GetStatusResponse, error) {
	return &agentv1.GetStatusResponse{}, nil
}
func (c *scriptedAgentClient) Close() error {
	if c.closed != nil {
		c.closed.Add(1)
	}
	return nil
}

func TestAgentWorkerRetriesBeyondFiveFailuresAndClosesClients(t *testing.T) {
	t.Parallel()
	var attempts, closes atomic.Int32
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.pull = IstioPullConfig{
		DialAgent: func(context.Context, string, string) (grpcexporter.AgentClientAPI, error) {
			return &scriptedAgentClient{
				scrape: func(context.Context) ([]*agentv1.Event, error) {
					attempts.Add(1)
					return nil, errors.New("temporary scrape error")
				},
				closed: &closes,
			}, nil
		},
		PollInterval: time.Second, ScrapeTimeout: time.Second,
	}
	scraper.jitter = func(time.Duration, float64) time.Duration { return 0 }
	scraper.wait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	ctx, cancel := context.WithCancel(context.Background())
	worker := &agentWorker{
		key:      k8stypes.NamespacedName{Namespace: "agents", Name: "unhealthy"},
		endpoint: "10.0.0.1:50052", authority: "unhealthy.agents", done: make(chan struct{}),
	}
	go scraper.runAgent(ctx, worker, make(chan struct{}, 1))
	require.Eventually(t, func() bool { return attempts.Load() >= 7 }, time.Second, time.Millisecond)
	select {
	case <-worker.done:
		t.Fatal("worker stopped after repeated transient errors")
	default:
	}
	cancel()
	select {
	case <-worker.done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
	require.Equal(t, attempts.Load(), closes.Load())
}

func TestAgentWorkersShareBoundedPermitsWithoutBlockingHealthyAgent(t *testing.T) {
	t.Parallel()
	var active, maximum, unhealthyAttempts, healthyAttempts, closes atomic.Int32
	updateMax := func(value int32) {
		for {
			current := maximum.Load()
			if value <= current || maximum.CompareAndSwap(current, value) {
				return
			}
		}
	}
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.pull = IstioPullConfig{
		PollInterval: time.Nanosecond, ScrapeTimeout: time.Second,
		DialAgent: func(_ context.Context, _, authority string) (grpcexporter.AgentClientAPI, error) {
			return &scriptedAgentClient{closed: &closes, scrape: func(context.Context) ([]*agentv1.Event, error) {
				current := active.Add(1)
				updateMax(current)
				time.Sleep(time.Millisecond)
				active.Add(-1)
				if authority == "unhealthy.agents" {
					unhealthyAttempts.Add(1)
					return nil, errors.New("agent is restarting")
				}
				healthyAttempts.Add(1)
				return []*agentv1.Event{}, nil
			}}, nil
		},
	}
	scraper.jitter = func(time.Duration, float64) time.Duration { return 0 }
	scraper.wait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	permits := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	workers := []*agentWorker{
		{
			key:       k8stypes.NamespacedName{Name: "unhealthy", Namespace: "agents"},
			authority: "unhealthy.agents",
			endpoint:  "10.0.0.1:50052",
			done:      make(chan struct{}),
		},
		{
			key:       k8stypes.NamespacedName{Name: "healthy", Namespace: "agents"},
			authority: "healthy.agents",
			endpoint:  "10.0.0.2:50052",
			done:      make(chan struct{}),
		},
	}
	for _, worker := range workers {
		go scraper.runAgent(ctx, worker, permits)
	}
	require.Eventually(
		t,
		func() bool { return unhealthyAttempts.Load() >= 6 && healthyAttempts.Load() > 0 },
		time.Second,
		time.Millisecond,
	)
	cancel()
	for _, worker := range workers {
		select {
		case <-worker.done:
		case <-time.After(time.Second):
			t.Fatal("agent worker did not stop after cancellation")
		}
	}
	require.LessOrEqual(t, maximum.Load(), int32(cap(permits)))
	require.Positive(t, healthyAttempts.Load())
	require.Equal(t, closes.Load(), unhealthyAttempts.Load()+healthyAttempts.Load())
}

func TestAgentWorkerRetryDelayResetsAfterSuccessfulEmptyScrape(t *testing.T) {
	t.Parallel()
	var scrapeCount atomic.Int32
	var waitCount atomic.Int32
	var delays []time.Duration
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.pull = IstioPullConfig{
		PollInterval: 8 * time.Second, ScrapeTimeout: time.Second,
		DialAgent: func(context.Context, string, string) (grpcexporter.AgentClientAPI, error) {
			return &scriptedAgentClient{scrape: func(context.Context) ([]*agentv1.Event, error) {
				if scrapeCount.Add(1) == 1 || scrapeCount.Load() == 3 {
					return nil, errors.New("temporary")
				}
				return []*agentv1.Event{}, nil
			}}, nil
		},
	}
	scraper.jitter = func(base time.Duration, _ float64) time.Duration {
		delays = append(delays, base)
		return 0
	}
	scraper.wait = func(context.Context, time.Duration) bool { return waitCount.Add(1) <= 3 }
	worker := &agentWorker{key: k8stypes.NamespacedName{Name: "agent", Namespace: "agents"}, done: make(chan struct{})}
	go scraper.runAgent(context.Background(), worker, make(chan struct{}, 1))
	select {
	case <-worker.done:
	case <-time.After(time.Second):
		t.Fatal("worker did not honor injected scheduler")
	}
	require.Equal(t, []time.Duration{4 * time.Second, time.Second, 8 * time.Second, time.Second}, delays)
}

func TestAgentWorkerCancellationWhileWaitingForPermit(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{}, 1)
	var dials atomic.Int32
	scraper := NewIstioScraper(IstioScraperConfig{Logger: slog.New(slog.DiscardHandler)})
	scraper.pull = IstioPullConfig{
		PollInterval: time.Nanosecond, ScrapeTimeout: time.Second,
		DialAgent: func(context.Context, string, string) (grpcexporter.AgentClientAPI, error) {
			dials.Add(1)
			return &scriptedAgentClient{scrape: func(ctx context.Context) ([]*agentv1.Event, error) {
				entered <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			}}, nil
		},
	}
	scraper.jitter = func(time.Duration, float64) time.Duration { return 0 }
	scraper.wait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	permits := make(chan struct{}, 1)
	permits <- struct{}{}
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	first := &agentWorker{key: k8stypes.NamespacedName{Name: "first", Namespace: "agents"}, done: make(chan struct{})}
	go scraper.runAgent(firstCtx, first, permits)
	cancelSecondCtx, cancelSecond := context.WithCancel(context.Background())
	second := &agentWorker{key: k8stypes.NamespacedName{Name: "second", Namespace: "agents"}, done: make(chan struct{})}
	go scraper.runAgent(cancelSecondCtx, second, permits)
	cancelSecond()
	cancelFirst()
	for _, worker := range []*agentWorker{first, second} {
		select {
		case <-worker.done:
		case <-time.After(time.Second):
			t.Fatal("worker did not cancel while waiting for a permit or RPC")
		}
	}
	require.LessOrEqual(t, dials.Load(), int32(1))
}
