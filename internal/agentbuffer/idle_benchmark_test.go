package agentbuffer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func benchmarkIdle10K(b *testing.B) *Buffer {
	b.Helper()
	buffer, _, err := Open(b.TempDir(), Config{
		Capacity: DefaultCapacity, MaxAge: DefaultMaxAge, MaxBytes: DefaultMaxBytes,
	})
	require.NoError(b, err)
	for range DefaultCapacity {
		buffer.StageLine(policyLine(protectDenyMessage, `,"policy":"ns/deny"`), time.Now())
	}
	require.NoError(b, buffer.CommitCheckpoint([]byte("idle benchmark checkpoint")))
	return buffer
}

func BenchmarkCommit10KIdle(b *testing.B) {
	buffer := benchmarkIdle10K(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := buffer.CommitCheckpoint([]byte("idle benchmark checkpoint")); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	require.NoError(b, buffer.Close())
}

func BenchmarkSweep10KIdle(b *testing.B) {
	buffer := benchmarkIdle10K(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := buffer.Sweep(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	require.NoError(b, buffer.Close())
}
