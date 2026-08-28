package ringbuf

import (
	"fmt"
	"testing"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/network-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/network-enforcer/internal/violation"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBufferRecordAndDrain(t *testing.T) {
	buf := New[violation.Observation]()

	buf.Record(violation.Observation{
		ViolationInfo: securityv1alpha1.ViolationInfo{
			Source:                 securityv1alpha1.WorkloadRef{Namespace: "ns1", OwnerName: "pod1"},
			Dest:                   securityv1alpha1.WorkloadRef{Namespace: "ns2", OwnerName: "svc1"},
			Protocol:               corev1.ProtocolTCP,
			DstPort:                80,
			Action:                 securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			DenyingPolicyName:      "deny-all",
			DenyingPolicyNamespace: "ns1",
		},
	})

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, "deny-all", records[0].DenyingPolicyName)
	require.Equal(t, int32(80), records[0].DstPort)

	// After drain, buffer should be empty.
	records = buf.Drain()
	require.Empty(t, records)
}

func TestBufferOverwritesOldest(t *testing.T) {
	size := 100
	buf := NewWithSize[violation.Observation](size)

	// Fill the buffer to capacity.
	for i := range size {
		dropped := buf.Record(violation.Observation{
			ViolationInfo: securityv1alpha1.ViolationInfo{
				Source:  securityv1alpha1.WorkloadRef{OwnerName: fmt.Sprintf("pod-%d", i)},
				Action:  securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				DstPort: int32(i),
			},
		})
		require.False(t, dropped, "should not drop while filling buffer")
	}

	// Add one more — should overwrite the oldest (pod-0).
	dropped := buf.Record(violation.Observation{
		ViolationInfo: securityv1alpha1.ViolationInfo{
			Source:  securityv1alpha1.WorkloadRef{OwnerName: "pod-overflow"},
			Action:  securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			DstPort: 9999,
		},
	})
	require.True(t, dropped, "should report a drop when buffer overflows")

	records := buf.Drain()
	require.Len(t, records, size)

	// Newest should be pod-overflow (first in newest-to-oldest order).
	require.Equal(t, "pod-overflow", records[0].Source.OwnerName)
	// Oldest should now be pod-1 (pod-0 was overwritten).
	require.Equal(t, "pod-1", records[len(records)-1].Source.OwnerName)
}

func TestBufferDrainReverseChronologicalOrder(t *testing.T) {
	buf := New[violation.Observation]()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		buf.Record(violation.Observation{
			ViolationInfo: securityv1alpha1.ViolationInfo{
				Timestamp: metav1.NewTime(baseTime.Add(time.Duration(i) * time.Second)),
				Source:    securityv1alpha1.WorkloadRef{OwnerName: fmt.Sprintf("pod-%d", i)},
				Action:    securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			},
		})
	}

	records := buf.Drain()
	require.Len(t, records, 5)
	for i, rec := range records {
		require.Equal(t, fmt.Sprintf("pod-%d", 4-i), rec.Source.OwnerName)
	}
}

func TestBufferDrainAfterOverflow(t *testing.T) {
	size := 80
	buf := NewWithSize[violation.Observation](size)

	totalRecords := size + 50

	for i := range totalRecords {
		buf.Record(violation.Observation{
			ViolationInfo: securityv1alpha1.ViolationInfo{
				Source: securityv1alpha1.WorkloadRef{OwnerName: fmt.Sprintf("pod-%d", i)},
				Action: securityv1alpha1.WorkloadNetworkPolicyModeProtect,
			},
		})
	}

	records := buf.Drain()
	require.Len(t, records, size)

	// The oldest 50 entries (pod-0 through pod-49) were overwritten.
	// Records should be in reverse chronological order: pod-(totalRecords-1), ..., pod-50.
	for i, rec := range records {
		expected := fmt.Sprintf("pod-%d", totalRecords-1-i)
		require.Equal(
			t,
			expected,
			rec.Source.OwnerName,
			"record at index %d should be %s, got %s",
			i,
			expected,
			rec.Source.OwnerName,
		)
	}
}

func TestConcurrentRecordAndDrain(_ *testing.T) {
	buf := New[violation.Observation]()

	done := make(chan struct{})

	// Concurrently record.
	go func() {
		for i := range 1000 {
			buf.Record(violation.Observation{
				ViolationInfo: securityv1alpha1.ViolationInfo{
					Source: securityv1alpha1.WorkloadRef{OwnerName: fmt.Sprintf("pod-%d", i)},
					Action: securityv1alpha1.WorkloadNetworkPolicyModeProtect,
				},
			})
		}
		close(done)
	}()

	// Concurrently drain (may see partial data, should not race).
	for range 10 {
		_ = buf.Drain()
	}

	<-done
	// Final drain should not panic.
	_ = buf.Drain()
}
