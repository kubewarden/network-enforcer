package istio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// sourcePod builds a client pod for resolution tests: an assigned pod IP,
// a service account, and an optional controller owner reference.
func sourcePod(name, namespace, ip, serviceAccount string, owner *metav1.OwnerReference) *corev1.Pod {
	pod := &corev1.Pod{
		Name:      name,
		Namespace: namespace,
		UID:       types.UID(name + "-uid"),
		Spec: corev1.PodSpec{
			ServiceAccountName: serviceAccount,
		},
		Status: corev1.PodStatus{
			PodIP: ip,
		},
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return pod
}

func TestIndexPodByIP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		obj  client.Object
		want []string
	}{
		{
			name: "pod with IP",
			obj:  sourcePod("p", "ns", "10.244.0.2", "sa", nil),
			want: []string{"10.244.0.2"},
		},
		{
			name: "pod without IP",
			obj:  sourcePod("p", "ns", "", "sa", nil),
			want: nil,
		},
		{
			name: "non-pod object",
			obj:  &corev1.Service{},
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, c.want, IndexPodByIP(c.obj))
		})
	}
}
