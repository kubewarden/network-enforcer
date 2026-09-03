package istio

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
)

// newTestLogger returns a [slog.Logger] that discards output, for enrichment
// tests that only care about the returned observation, not the logs.
func newTestLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// errFake is returned by the erroring fake clients below to exercise the
// unexpected-error branch of resolveSourceWorkload and the destination fetch.
var errFake = errors.New("boom")

// newEnricherScheme builds a scheme with the core, apps, networking and
// security types used by the enrichment tests.
func newEnricherScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = securityv1alpha1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = scheme.AddToScheme(s) // core/v1
	return s
}

// newEnricherWithObjects builds an Enricher backed by a fake client seeded with
// the given objects. The status.podIP field index is registered so source
// resolution behaves as it does in production.
func newEnricherWithObjects(objs ...client.Object) *Enricher {
	return NewEnricher(fake.NewClientBuilder().
		WithScheme(newEnricherScheme()).
		WithIndex(&corev1.Pod{}, PodIPIndexField, IndexPodByIP).
		WithObjects(objs...).
		Build())
}

// newEnricherWithListError builds an Enricher whose pod List always fails, to
// exercise the unexpected-error path of resolveSourceWorkload.
func newEnricherWithListError() *Enricher {
	return NewEnricher(fake.NewClientBuilder().
		WithScheme(newEnricherScheme()).
		WithIndex(&corev1.Pod{}, PodIPIndexField, IndexPodByIP).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return errFake
			},
		}).
		Build())
}

// newEnricherWithGetError builds an Enricher whose Get always fails with a
// non-NotFound error, to exercise the unexpected-error path of the destination
// pod fetch.
func newEnricherWithGetError() *Enricher {
	return NewEnricher(fake.NewClientBuilder().
		WithScheme(newEnricherScheme()).
		WithIndex(&corev1.Pod{}, PodIPIndexField, IndexPodByIP).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return errFake
			},
		}).
		Build())
}

// controllerRef builds a controller owner reference for the given workload.
func controllerRef(apiVersion, kind, name string) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		UID:        types.UID(name + "-uid"),
		Controller: new(true),
	}
}

// deploymentPod builds a pod owned by a ReplicaSet with a pod-template-hash so
// ExtractWorkloadKey resolves it to the owning Deployment.
func deploymentPod(deployName, namespace, ip, serviceAccount string) *corev1.Pod {
	const hash = "abc123"
	rsName := deployName + "-" + hash
	pod := sourcePod(rsName+"-pod", namespace, ip, serviceAccount,
		controllerRef(appsv1.SchemeGroupVersion.String(), string(securityv1alpha1.WorkloadKindReplicaSet), rsName))
	pod.Labels = map[string]string{appsv1.DefaultDeploymentUniqueLabelKey: hash}
	return pod
}

// destPod builds a Deployment-owned pod carrying the given selector labels, for
// ALLOW-miss correlation tests that match a destination pod against WNP
// selectors. It has no pod IP because destination resolution fetches it by name.
func destPod(deployName, namespace, serviceAccount string, matchLabels map[string]string) *corev1.Pod {
	pod := deploymentPod(deployName, namespace, "", serviceAccount)
	maps.Copy(pod.Labels, matchLabels)
	return pod
}

// istioWNP builds an Istio-backend WorkloadNetworkPolicy whose selector matches
// the given labels, for ALLOW-miss owning-policy resolution tests.
func istioWNP(namespace, name string, matchLabels map[string]string) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		Name: name, Namespace: namespace,
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendIstio,
				Istio: &securityv1alpha1.IstioAuthorizationPolicySpec{
					Selector: metav1.LabelSelector{MatchLabels: matchLabels},
				},
			},
		},
	}
}

// kubernetesWNP builds a Kubernetes-backend WorkloadNetworkPolicy whose pod
// selector matches the given labels, for ALLOW-miss owning-policy resolution
// tests of the kubernetes backend.
func kubernetesWNP(namespace, name string, matchLabels map[string]string) *securityv1alpha1.WorkloadNetworkPolicy {
	return &securityv1alpha1.WorkloadNetworkPolicy{
		Name: name, Namespace: namespace,
		Spec: securityv1alpha1.WorkloadNetworkPolicySpec{
			PolicyBackendSpec: securityv1alpha1.PolicyBackendSpec{
				Backend: securityv1alpha1.PolicyBackendKubernetes,
				Kubernetes: &networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: matchLabels},
				},
			},
		},
	}
}

func TestResolveSourceWorkload(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		objs []client.Object
		// enricher overrides the default enricher (built from objs) for cases that
		// need an erroring client.
		enricher   *Enricher
		obs        violation.Observation
		wantErr    bool
		wantSource securityv1alpha1.WorkloadRef
	}{
		{
			name: "IP resolves to one deployment pod",
			objs: []client.Object{
				deploymentPod("myapp", "team-a", "10.244.0.2", "myapp-sa"),
			},
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.2:40422"},
				},
			},
			wantSource: securityv1alpha1.WorkloadRef{
				Namespace: "team-a",
				OwnerKind: securityv1alpha1.WorkloadKindDeployment,
				OwnerName: "myapp",
				Identity:  "cluster.local/ns/team-a/sa/myapp-sa",
			},
		},
		{
			name: "IP resolves to one standalone pod with default service account",
			objs: []client.Object{
				sourcePod("lonely", "team-b", "10.244.0.3", "", nil),
			},
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.3:1234"},
				},
			},
			wantSource: securityv1alpha1.WorkloadRef{
				Namespace: "team-b",
				OwnerKind: securityv1alpha1.WorkloadKindPod,
				OwnerName: "lonely",
				Identity:  "cluster.local/ns/team-b/sa/default",
			},
		},
		{
			name: "IP resolves to no pod is an error",
			objs: nil,
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.9.9:5555"},
				},
			},
			wantErr: true,
		},
		{
			name: "IP resolves to multiple pods is an error",
			objs: []client.Object{
				sourcePod("zeta", "ns-b", "10.244.0.5", "sa-z", nil),
				sourcePod("alpha", "ns-a", "10.244.0.5", "sa-a", nil),
			},
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.5:9000"},
				},
			},
			wantErr: true,
		},
		{
			name: "source name is not ip:port is an error",
			objs: nil,
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "some-workload"},
				},
			},
			wantErr: true,
		},
		{
			name:     "list error is returned to caller",
			enricher: newEnricherWithListError(),
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.2:40422"},
				},
			},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			e := c.enricher
			if e == nil {
				e = newEnricherWithObjects(c.objs...)
			}
			src, err := e.resolveSourceWorkload(context.Background(), c.obs)

			if c.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, c.wantSource, src)
			}
		})
	}
}

func TestResolveOwningPolicy(t *testing.T) {
	t.Parallel()

	// pod is the ALLOW-miss destination whose labels are matched against WNP
	// selectors. It carries app=frontend.
	pod := destPod("frontend", "ns-dst", "frontend-sa", map[string]string{"app": "frontend"})

	cases := []struct {
		name string
		objs []client.Object
		// enricher overrides the default enricher (built from objs) for the
		// list-error case.
		enricher *Enricher
		wantErr  bool
		wantNS   string
		wantName string
	}{
		{
			// A same-labelled WNP in another namespace must be ignored: correlation
			// is scoped to the destination pod's namespace.
			name: "single istio WNP selects the pod, cross-namespace WNP ignored",
			objs: []client.Object{
				istioWNP("ns-dst", "user-named-wnp", map[string]string{"app": "frontend"}),
				istioWNP("other-ns", "decoy-wnp", map[string]string{"app": "frontend"}),
			},
			wantNS:   "ns-dst",
			wantName: "user-named-wnp",
		},
		{
			// A Kubernetes-backend WNP is never correlated on the Istio path, even when
			// its selector would match, so it is skipped and leaves the owner unresolved.
			name: "kubernetes-backend WNP is ignored",
			objs: []client.Object{
				kubernetesWNP("ns-dst", "k8s-wnp", map[string]string{"app": "frontend"}),
			},
			wantErr: true,
		},
		{
			name: "multiple matching WNPs pick the first sorted by name",
			objs: []client.Object{
				istioWNP("ns-dst", "bbb-wnp", map[string]string{"app": "frontend"}),
				istioWNP("ns-dst", "aaa-wnp", map[string]string{"app": "frontend"}),
			},
			wantNS:   "ns-dst",
			wantName: "aaa-wnp",
		},
		{
			name: "empty selector is skipped and never matches",
			objs: []client.Object{
				istioWNP("ns-dst", "catch-all", map[string]string{}),
			},
			wantErr: true,
		},
		{
			name: "no WNP selects the pod",
			objs: []client.Object{
				istioWNP("ns-dst", "other-wnp", map[string]string{"app": "other"}),
			},
			wantErr: true,
		},
		{
			name:     "list error is returned to caller",
			enricher: newEnricherWithListError(),
			wantErr:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			e := c.enricher
			if e == nil {
				e = newEnricherWithObjects(c.objs...)
			}
			owner, err := e.resolveOwningPolicy(context.Background(), newTestLogger(), pod)

			if c.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, c.wantNS, owner.Namespace)
				assert.Equal(t, c.wantName, owner.Name)
			}
		})
	}
}

func TestEnrich(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		objs []client.Object
		// enricher overrides the default enricher (built from objs) for the
		// nil-client and erroring-client cases.
		enricher *Enricher
		// nilEnricher forces a typed-nil *Enricher receiver for the nil passthrough
		// case.
		nilEnricher bool
		obs         violation.Observation
		want        violation.Observation
	}{
		{
			// The source (by peer IP), the destination (by pod name), and the owning
			// WNP (by selector match on the dest pod) all resolve. WNP violations are
			// always ALLOW-miss, so the owning WNP is recorded in the DenyingPolicy
			// fields. Uses ns-app for the destination to confirm the dest fetch and
			// WNP search are scoped to the destination's own namespace.
			name: "resolves source, dest, and owning WNP",
			objs: []client.Object{
				deploymentPod("client", "ns-src", "10.244.0.2", "client-sa"),
				destPod("server", "ns-app", "server-sa", map[string]string{"app": "server"}),
				istioWNP("ns-app", "user-named-wnp", map[string]string{"app": "server"}),
			},
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.2:40422"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-app",
						OwnerName: "server-abc123-pod",
					},
				},
			},
			want: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{
						Namespace: "ns-src",
						OwnerKind: "Deployment",
						OwnerName: "client",
						Identity:  "cluster.local/ns/ns-src/sa/client-sa",
					},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-app",
						OwnerKind: "Deployment",
						OwnerName: "server",
						Identity:  "cluster.local/ns/ns-app/sa/server-sa",
					},
					DenyingPolicyNamespace: "ns-app",
					DenyingPolicyName:      "user-named-wnp",
				},
			},
		},
		{
			// An ALLOW-miss whose dest pod matches no WNP selector leaves the owning
			// policy unresolved (the controller then drops it).
			name: "ALLOW-miss with no matching WNP leaves policy empty",
			objs: []client.Object{
				destPod("orphan", "ns-dst", "orphan-sa", map[string]string{"app": "orphan"}),
				istioWNP("ns-dst", "other-wnp", map[string]string{"app": "other"}),
			},
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "some-external-source"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "orphan-abc123-pod",
					},
				},
			},
			want: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "some-external-source"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerKind: "Deployment",
						OwnerName: "orphan",
						Identity:  "cluster.local/ns/ns-dst/sa/orphan-sa",
					},
				},
			},
		},
		{
			// Source has no pod and the dest pod does not exist (NotFound): both keep
			// their raw values and no owning policy is resolved.
			name: "keeps raw values when source and dest lookups fail",
			objs: nil,
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.9.9:5555"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "gone-pod",
					},
				},
			},
			want: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.9.9:5555"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "gone-pod",
					},
				},
			},
		},
		{
			// A non-NotFound dest Get error is logged and the raw destination kept.
			name:     "dest fetch error keeps raw destination",
			enricher: newEnricherWithGetError(),
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "some-external-source"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "server-abc123-pod",
					},
				},
			},
			want: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "some-external-source"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "server-abc123-pod",
					},
				},
			},
		},
		{
			// A dest carrying an empty namespace or pod name cannot be fetched, so the
			// enricher leaves it raw and resolves no owning policy (the controller then
			// drops the uncorrelatable observation).
			name: "empty dest namespace skips dest enrichment",
			objs: []client.Object{
				istioWNP("ns-dst", "user-named-wnp", map[string]string{"app": "server"}),
			},
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "some-external-source"},
					Dest:   securityv1alpha1.WorkloadRef{OwnerName: "server-abc123-pod"},
				},
			},
			want: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "some-external-source"},
					Dest:   securityv1alpha1.WorkloadRef{OwnerName: "server-abc123-pod"},
				},
			},
		},
		{
			name:        "nil enricher is a no-op passthrough",
			nilEnricher: true,
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.2:40422"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "server-pod",
					},
				},
			},
			want: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.2:40422"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "server-pod",
					},
				},
			},
		},
		{
			name:     "enricher with nil client is a no-op passthrough",
			enricher: &Enricher{},
			obs: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.2:40422"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "server-pod",
					},
				},
			},
			want: violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: "10.244.0.2:40422"},
					Dest: securityv1alpha1.WorkloadRef{
						Namespace: "ns-dst",
						OwnerName: "server-pod",
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			var e *Enricher
			switch {
			case c.nilEnricher:
				e = nil
			case c.enricher != nil:
				e = c.enricher
			default:
				e = newEnricherWithObjects(c.objs...)
			}
			got := e.Enrich(context.Background(), newTestLogger(), c.obs)
			assert.Equal(t, c.want, got)
		})
	}
}
