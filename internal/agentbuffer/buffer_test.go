package agentbuffer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

const (
	learnMessage       = "connection complete"
	monitorDenyMessage = "dry-run: deny policy match"
	protectDenyMessage = "deny policy match"
)

func testConfig() Config {
	return Config{Capacity: 10, MaxAge: time.Minute, MaxBytes: 2 << 20,
		Now: func() time.Time { return time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC) }}
}

func openTestBuffer(t *testing.T, dir string, config Config) (*Buffer, bool) {
	t.Helper()
	b, recovered, err := Open(dir, config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b, recovered
}

func rewriteEnvelopeState(
	t *testing.T,
	dir string,
	updateChecksum bool,
	mutate func(map[string]json.RawMessage),
) []byte {
	t.Helper()
	path := filepath.Join(dir, stateFileName)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var envelope diskEnvelope
	require.NoError(t, json.Unmarshal(raw, &envelope))
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope.State, &fields))
	mutate(fields)
	envelope.State, err = json.Marshal(fields)
	require.NoError(t, err)
	if updateChecksum {
		checksum := sha256.Sum256(envelope.State)
		envelope.Checksum = hex.EncodeToString(checksum[:])
	}
	raw, err = json.Marshal(envelope)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return raw
}

func policyLine(message, extra string) []byte {
	body := `{"message":"` + message + `","proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}` + extra + `}`
	return []byte("2026-11-02T00:00:00.123Z stdout F " + body)
}

func commitPolicies(t *testing.T, b *Buffer, count int) {
	t.Helper()
	for range count {
		b.StageLine(policyLine(protectDenyMessage, `,"policy":"ns/deny"`), time.Time{})
	}
	require.NoError(t, b.CommitCheckpoint([]byte("opaque stanza offsets")))
}

func TestOpenFreshVersusRecoveredEmptyState(t *testing.T) {
	dir := t.TempDir()
	first, recovered := openTestBuffer(t, dir, testConfig())
	require.False(t, recovered)
	firstEpoch := first.state.Epoch
	require.NotEmpty(t, firstEpoch)
	require.Equal(t, uint64(1), first.Counters()["epoch_resets"])
	require.NoError(t, first.Close())

	second, recovered, err := Open(dir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered, "an empty checkpoint must still reopen from beginning")
	require.Equal(t, firstEpoch, second.state.Epoch)
	require.Equal(t, uint64(1), second.Counters()["epoch_resets"], "container restart is not a new epoch")
	require.Zero(t, second.state.NewestSeq)
	require.NoError(t, second.Close())
}

func TestReplacementStateVolumeStartsNewEpoch(t *testing.T) {
	dir := t.TempDir()
	first, fresh := openTestBuffer(t, dir, testConfig())
	require.False(t, fresh)
	firstEpoch := first.state.Epoch
	require.NoError(t, first.Close())
	require.NoError(t, os.RemoveAll(dir))

	replacement, fresh, err := Open(dir, testConfig())
	require.NoError(t, err)
	require.False(t, fresh)
	require.NotEqual(t, firstEpoch, replacement.state.Epoch)
	require.NoError(t, replacement.Close())
}

func TestMissingSnapshotWithExistingLockMarkerIsNotFreshTailStart(t *testing.T) {
	dir := t.TempDir()
	first, fresh := openTestBuffer(t, dir, testConfig())
	require.False(t, fresh)
	firstEpoch := first.state.Epoch
	require.NoError(t, first.Close())
	require.NoError(t, os.Remove(filepath.Join(dir, stateFileName)))

	reopened, resumed, err := Open(dir, testConfig())
	require.NoError(t, err)
	require.True(t, resumed, "the durable lock marker proves this is a reopened state directory")
	require.NotEqual(t, firstEpoch, reopened.state.Epoch, "missing state begins a fresh epoch")
	require.NoError(t, reopened.Close())
}

func TestOpenCleansOnlyStaleStateTemporaryFilesAfterLock(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".agent-state-stale")
	unrelated := filepath.Join(dir, "unrelated.tmp")
	matchingDir := filepath.Join(dir, ".agent-state-directory")
	matchingLink := filepath.Join(dir, ".agent-state-link")
	require.NoError(t, os.WriteFile(stale, []byte("stale"), 0o600))
	require.NoError(t, os.WriteFile(unrelated, []byte("keep"), 0o600))
	require.NoError(t, os.Mkdir(matchingDir, 0o700))
	require.NoError(t, os.Symlink(unrelated, matchingLink))

	b, _ := openTestBuffer(t, dir, testConfig())
	_, err := os.Stat(stale)
	require.True(t, os.IsNotExist(err))
	require.FileExists(t, unrelated)
	require.DirExists(t, matchingDir)
	_, err = os.Lstat(matchingLink)
	require.NoError(t, err)
	require.NoError(t, b.Close())
}

func TestOpenEnforcesOneStateWriter(t *testing.T) {
	dir := t.TempDir()
	first, _ := openTestBuffer(t, dir, testConfig())
	stale := filepath.Join(dir, ".agent-state-active-writer")
	require.NoError(t, os.WriteFile(stale, []byte("owned by active writer"), 0o600))
	_, _, err := Open(dir, testConfig())
	require.ErrorContains(t, err, "lock agent state directory")
	require.FileExists(t, stale, "a failed lock attempt must not clean another writer's temporary")
	require.NoError(t, first.Close())
	reopened, _, err := Open(dir, testConfig())
	require.NoError(t, err)
	require.NoFileExists(t, stale)
	require.NoError(t, reopened.Close())
}

func TestPendingEventsNeverExposeOrAcceptTheirSequenceBeforeCheckpoint(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	b.StageLine(policyLine(protectDenyMessage, ``), time.Time{})
	resp, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Zero(t, resp.GetNewestSeq())
	require.Empty(t, resp.GetEvents())
	_, err = b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 1})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Zero(t, b.state.AckedSeq)
	require.NoError(t, b.CommitCheckpoint([]byte("offset")))
	resp, err = b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(1), resp.GetNewestSeq())
	require.Equal(t, uint64(1), resp.GetEvents()[0].GetSeq())
}

func TestPullBootstrapAckGapAndMonotonicCursor(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	commitPolicies(t, b, 3)

	bootstrap, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(0), bootstrap.GetAckedSeq())
	require.Len(t, bootstrap.GetEvents(), 3)
	require.False(t, bootstrap.GetGap())

	stale, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 2})
	require.NoError(t, err)
	require.Equal(t, uint64(2), stale.GetAckedSeq())
	require.Len(t, stale.GetEvents(), 1)

	stale, err = b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 1})
	require.NoError(t, err)
	require.Equal(t, uint64(2), stale.GetAckedSeq(), "stale cursor cannot rewind")
	require.Len(t, stale.GetEvents(), 1)
	status, err := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(2), status.GetAckedSeq())
}

func TestPullValidatesBeforeMutationIncludingMismatchMaxUint64(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	commitPolicies(t, b, 2)
	bad := []struct {
		name string
		req  *agentv1.PullEventsRequest
	}{
		{"bootstrap cursor", &agentv1.PullEventsRequest{SinceSeq: 1}},
		{"limit", &agentv1.PullEventsRequest{Limit: MaximumPullLimit + 1}},
		{"future cursor", &agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 3}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			before := cloneState(b.state)
			_, err := b.PullEvents(context.Background(), tc.req)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			require.True(t, equalState(before, b.state), "invalid request changed durable state")
		})
	}
	mismatch, err := b.PullEvents(
		context.Background(),
		&agentv1.PullEventsRequest{Epoch: "old-epoch", SinceSeq: math.MaxUint64},
	)
	require.NoError(t, err)
	require.True(t, mismatch.GetGap())
	require.Equal(t, uint64(0), mismatch.GetAckedSeq())
	require.Len(t, mismatch.GetEvents(), 2)
}

func TestGapAckAndRepeatedGapReportsAreNotDropCounts(t *testing.T) {
	cfg := testConfig()
	cfg.Capacity = 2
	b, _ := openTestBuffer(t, t.TempDir(), cfg)
	commitPolicies(t, b, 4)
	writes := 0
	b.syncDir = func(path string) error {
		writes++
		return syncStateDirectory(path)
	}
	require.Equal(t, uint64(2), b.state.DroppedEvents)
	first, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch})
	require.NoError(t, err)
	require.True(t, first.GetGap())
	require.Equal(t, uint64(2), first.GetDropped())
	require.Equal(t, uint64(3), first.GetEvents()[0].GetSeq())
	second, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch})
	require.NoError(t, err)
	require.Equal(t, first.GetDropped(), second.GetDropped())
	require.Equal(t, uint64(2), b.state.DroppedEvents, "retry reports are not fresh evictions")
	require.Equal(t, uint64(2), b.Counters()["retention_gap_reports"])
	require.Zero(t, writes, "repeated gap reports must not rewrite durable state")

	acceptedGap, err := b.PullEvents(
		context.Background(),
		&agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 2},
	)
	require.NoError(t, err)
	require.False(t, acceptedGap.GetGap())
	require.Equal(t, uint64(2), acceptedGap.GetAckedSeq())
	require.Equal(t, uint64(0), acceptedGap.GetDropped())
	require.Len(t, acceptedGap.GetEvents(), 2)
	require.NoError(t, b.Close())
	reopened, recovered, err := Open(filepath.Dir(b.path), testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	require.Zero(t, reopened.Counters()["retention_gap_reports"], "report counters are process-lifetime only")
	require.NoError(t, reopened.Close())
}

func TestEpochMismatchIgnoresCursorAndUsesStoredAck(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	commitPolicies(t, b, 3)
	_, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 2})
	require.NoError(t, err)
	resp, err := b.PullEvents(
		context.Background(),
		&agentv1.PullEventsRequest{Epoch: "different", SinceSeq: math.MaxUint64},
	)
	require.NoError(t, err)
	require.True(t, resp.GetGap())
	require.Equal(t, uint64(2), resp.GetAckedSeq())
	require.Len(t, resp.GetEvents(), 1)
	require.Equal(t, uint64(3), resp.GetEvents()[0].GetSeq())
}

func TestFilteredRecordsCountWithoutSequenceAndPayloadIsCloned(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	b.StageLine([]byte(`{"message":"ordinary ignored log"}`), time.Time{})
	raw := policyLine(protectDenyMessage, `,"policy":"ns/deny"`)
	b.StageLine(raw, time.Time{})
	require.NoError(t, b.CommitCheckpoint(nil))
	raw[len(raw)-2] = 'X'
	resp, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetEvents(), 1)
	require.Equal(t, uint64(1), resp.GetEvents()[0].GetSeq())
	require.Equal(t, uint64(2), b.state.ReceivedEvents)
	require.Equal(t, protectDenyMessage, resp.GetEvents()[0].GetPolicy().GetMessage())
	require.Contains(t, string(resp.GetEvents()[0].GetRawRecord()), protectDenyMessage)
}

func TestOversizedEventRejectedAndSinglePollOverflowKeepsNewestSuffix(t *testing.T) {
	cfg := testConfig()
	cfg.Capacity = 2
	b, _ := openTestBuffer(t, t.TempDir(), cfg)
	for range 7 {
		b.StageLine(policyLine(protectDenyMessage, `,"policy":"ns/`+strings.Repeat("p", 20)+`"`), time.Time{})
	}
	require.NoError(t, b.CommitCheckpoint(nil))
	require.Equal(t, uint64(7), b.state.NewestSeq)
	require.Equal(t, uint64(5), b.state.DroppedEvents)
	resp, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, []uint64{6, 7}, []uint64{resp.GetEvents()[0].GetSeq(), resp.GetEvents()[1].GetSeq()})

	tooLarge := `,"padding":"` + strings.Repeat("x", MaxEventBytes+100) + `"`
	b.StageLine(policyLine(protectDenyMessage, tooLarge), time.Time{})
	require.NoError(t, b.CommitCheckpoint(nil))
	require.Equal(t, uint64(7), b.state.NewestSeq, "oversize records do not get identities")
	require.Equal(t, uint64(1), b.Counters()["rejected_events"])
}

func TestByteCapMaintainsPrefixContiguity(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBytes = MaxEventBytes
	cfg.Capacity = 10
	b, _ := openTestBuffer(t, t.TempDir(), cfg)
	padding := strings.Repeat("x", 600_000)
	for range 2 {
		b.StageLine(policyLine(protectDenyMessage, `,"padding":"`+padding+`"`), time.Time{})
	}
	require.NoError(t, b.CommitCheckpoint(nil))
	require.Equal(t, uint64(2), b.state.NewestSeq)
	require.Len(t, b.state.Events, 1)
	require.Equal(t, uint64(1), b.state.DroppedEvents)
	resp, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(2), resp.GetEvents()[0].GetSeq())
}

func TestPendingByteOverflowEvictsCommittedPrefixAndPreservesGapAcrossRestart(t *testing.T) {
	for _, ackOld := range []bool{false, true} {
		name := "unacked-old"
		wantDropped := uint64(2)
		if ackOld {
			name = "acked-old"
			wantDropped = 1
		}
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Capacity = 10
			cfg.MaxBytes = MaxEventBytes
			dir := t.TempDir()
			b, _ := openTestBuffer(t, dir, cfg)
			commitPolicies(t, b, 1)
			if ackOld {
				_, err := b.PullEvents(
					context.Background(),
					&agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 1},
				)
				require.NoError(t, err)
			}
			committedBacking := b.state.Events
			b.pending = make([]pendingEvent, 0, 4)
			pendingBacking := b.pending[:cap(b.pending)]
			largePadding := strings.Repeat("x", 600_000)
			b.StageLine(policyLine(protectDenyMessage, `,"padding":"`+largePadding+`"`), time.Time{})
			b.StageLine(policyLine(protectDenyMessage, `,"padding":"`+largePadding+`"`), time.Time{})
			b.StageLine(policyLine(protectDenyMessage, ``), time.Time{})
			require.Equal(t, uint64(1), b.pendingDrop)
			require.Nil(t, pendingBacking[0].payload, "evicted pending slots must release payload references")
			require.NoError(t, b.CommitCheckpoint([]byte("offset-after-overflow")))
			require.Equal(t, uint64(4), b.state.NewestSeq)
			require.Equal(t, wantDropped, b.state.DroppedEvents)
			require.Equal(t, []uint64{3, 4}, storedSequences(t, b.state.Events))
			require.NotEmpty(
				t,
				committedBacking[0].Payload,
				"candidate pruning must not mutate committed slice backing storage",
			)
			oldEvent := &agentv1.Event{}
			require.NoError(t, proto.Unmarshal(committedBacking[0].Payload, oldEvent))
			require.Equal(t, uint64(1), oldEvent.GetSeq())

			response, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch})
			require.NoError(t, err)
			require.True(t, response.GetGap())
			wantGap := uint64(2)
			if ackOld {
				wantGap = 1
			}
			require.Equal(t, wantGap, response.GetDropped())
			require.Equal(t, []uint64{3, 4}, eventSequences(response.GetEvents()))
			require.NoError(t, b.Close())

			reopened, recovered, err := Open(dir, cfg)
			require.NoError(t, err)
			require.True(t, recovered)
			require.Equal(t, wantDropped, reopened.state.DroppedEvents)
			reopenedGap, err := reopened.PullEvents(
				context.Background(),
				&agentv1.PullEventsRequest{Epoch: reopened.state.Epoch},
			)
			require.NoError(t, err)
			require.True(t, reopenedGap.GetGap())
			require.Equal(t, wantGap, reopenedGap.GetDropped())
			require.Equal(t, []uint64{3, 4}, storedSequences(t, reopened.state.Events))
			require.NoError(t, reopened.Close())
		})
	}
}

func TestPendingByteOverflowAtDefaultLimitDropsEntireOldPrefix(t *testing.T) {
	cfg := Config{Capacity: DefaultCapacity, MaxAge: DefaultMaxAge, MaxBytes: DefaultMaxBytes}
	dir := t.TempDir()
	b, _ := openTestBuffer(t, dir, cfg)
	commitPolicies(t, b, 1)
	padding := strings.Repeat("x", 800_000)
	for range 21 {
		b.StageLine(policyLine(protectDenyMessage, `,"padding":"`+padding+`"`), time.Time{})
	}
	require.Equal(t, uint64(1), b.pendingDrop)
	require.NoError(t, b.CommitCheckpoint([]byte("default-byte-limit-offset")))
	require.Equal(t, uint64(22), b.state.NewestSeq)
	require.Equal(t, uint64(2), b.state.DroppedEvents)
	require.Len(t, b.state.Events, 20)
	require.Equal(t, uint64(3), firstStoredSeq(b.state.Events))
	require.NoError(t, b.Close())

	reopened, recovered, err := Open(dir, cfg)
	require.NoError(t, err)
	require.True(t, recovered)
	require.Equal(t, uint64(22), reopened.state.NewestSeq)
	require.Equal(t, uint64(2), reopened.state.DroppedEvents)
	require.Equal(t, uint64(3), firstStoredSeq(reopened.state.Events))
	require.NoError(t, reopened.Close())
}

func storedSequences(t *testing.T, events []storedEvent) []uint64 {
	t.Helper()
	sequences := make([]uint64, 0, len(events))
	for _, stored := range events {
		event := &agentv1.Event{}
		require.NoError(t, proto.Unmarshal(stored.Payload, event))
		sequences = append(sequences, event.GetSeq())
	}
	return sequences
}

func eventSequences(events []*agentv1.Event) []uint64 {
	sequences := make([]uint64, 0, len(events))
	for _, event := range events {
		sequences = append(sequences, event.GetSeq())
	}
	return sequences
}

func firstStoredSeq(events []storedEvent) uint64 {
	if len(events) == 0 {
		return 0
	}
	event := &agentv1.Event{}
	_ = proto.Unmarshal(events[0].Payload, event)
	return event.GetSeq()
}

func TestResponseByteBudgetTruncatesOnlyTheEnd(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBytes = 8 << 20
	cfg.Capacity = 20
	b, _ := openTestBuffer(t, t.TempDir(), cfg)
	padding := strings.Repeat("x", 850_000)
	for range 6 {
		b.StageLine(policyLine(protectDenyMessage, `,"padding":"`+padding+`"`), time.Time{})
	}
	require.NoError(t, b.CommitCheckpoint(nil))
	resp, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Limit: 10})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetEvents())
	require.Less(t, len(resp.GetEvents()), 6)
	require.LessOrEqual(t, proto.Size(resp), MaxResponseBytes)
	for i, event := range resp.GetEvents() {
		require.Equal(t, uint64(i+1), event.GetSeq())
	}
}

func TestAckAndEventsSurviveReopenAndStartupCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	b, _ := openTestBuffer(t, dir, testConfig())
	commitPolicies(t, b, 2)
	_, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b.state.Epoch, SinceSeq: 1})
	require.NoError(t, err)
	epoch := b.state.Epoch
	require.NoError(t, b.Close())

	reopened, recovered, err := Open(dir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	require.Equal(t, epoch, reopened.state.Epoch)
	require.Equal(t, uint64(1), reopened.state.AckedSeq)
	require.Equal(t, uint64(2), reopened.state.NewestSeq)
	resp, err := reopened.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: epoch})
	require.NoError(t, err)
	require.Equal(t, uint64(1), resp.GetAckedSeq())
	require.Len(t, resp.GetEvents(), 1)
	require.Equal(t, uint64(2), resp.GetEvents()[0].GetSeq())
	require.NoError(t, reopened.Close())

	rewriteEnvelopeState(t, dir, true, func(fields map[string]json.RawMessage) {
		fields["version"] = json.RawMessage("99")
	})
	_, _, err = Open(dir, testConfig())
	require.ErrorContains(t, err, "unsupported state version")
}

func TestSnapshotChecksumAndRequiredFieldsFailClosedWithoutRewrite(t *testing.T) {
	cases := []struct {
		name   string
		field  string
		remove bool
	}{
		{name: "missing epoch", field: "epoch", remove: true},
		{name: "missing ack", field: "ackedSeq", remove: true},
		{name: "null newest", field: "newestSeq"},
		{name: "missing received counter", field: "receivedEvents", remove: true},
		{name: "null dropped counter", field: "droppedEvents"},
		{name: "null rejected counter", field: "rejectedEvents"},
		{name: "missing known files", field: "knownFiles", remove: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b, _ := openTestBuffer(t, dir, testConfig())
			require.NoError(t, b.Close())
			raw := rewriteEnvelopeState(t, dir, true, func(fields map[string]json.RawMessage) {
				if tc.remove {
					delete(fields, tc.field)
				} else {
					fields[tc.field] = json.RawMessage("null")
				}
			})
			_, _, err := Open(dir, testConfig())
			require.Error(t, err)
			unchanged, readErr := os.ReadFile(filepath.Join(dir, stateFileName))
			require.NoError(t, readErr)
			require.Equal(t, raw, unchanged, "failed Open must not rewrite the corrupted snapshot")
		})
	}

	t.Run("changed knownFiles checksum", func(t *testing.T) {
		dir := t.TempDir()
		b, _ := openTestBuffer(t, dir, testConfig())
		commitPolicies(t, b, 1)
		require.NoError(t, b.Close())
		raw := rewriteEnvelopeState(t, dir, false, func(fields map[string]json.RawMessage) {
			fields["knownFiles"] = json.RawMessage(`"CgA="`)
		})
		_, _, err := Open(dir, testConfig())
		require.ErrorContains(t, err, "checksum mismatch")
		unchanged, readErr := os.ReadFile(filepath.Join(dir, stateFileName))
		require.NoError(t, readErr)
		require.Equal(t, raw, unchanged)
	})

	t.Run("changed payload checksum", func(t *testing.T) {
		dir := t.TempDir()
		b, _ := openTestBuffer(t, dir, testConfig())
		commitPolicies(t, b, 1)
		require.NoError(t, b.Close())
		raw := rewriteEnvelopeState(t, dir, false, func(fields map[string]json.RawMessage) {
			var events []map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(fields["events"], &events))
			var payload []byte
			require.NoError(t, json.Unmarshal(events[0]["payload"], &payload))
			payload[len(payload)-1] ^= 0x01
			events[0]["payload"], _ = json.Marshal(payload)
			fields["events"], _ = json.Marshal(events)
		})
		_, _, err := Open(dir, testConfig())
		require.ErrorContains(t, err, "checksum mismatch")
		unchanged, readErr := os.ReadFile(filepath.Join(dir, stateFileName))
		require.NoError(t, readErr)
		require.Equal(t, raw, unchanged)
	})
}

func TestEmptyAfterExpiryAlsoRequiresPersistedCounters(t *testing.T) {
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	cfg := testConfig()
	cfg.Now = func() time.Time { return now }
	dir := t.TempDir()
	b, _ := openTestBuffer(t, dir, cfg)
	commitPolicies(t, b, 1)
	now = now.Add(2 * time.Minute)
	require.NoError(t, b.Sweep())
	require.Empty(t, b.state.Events)
	require.NoError(t, b.Close())
	rewriteEnvelopeState(t, dir, true, func(fields map[string]json.RawMessage) {
		delete(fields, "ackedSeq")
	})
	_, _, err := Open(dir, cfg)
	require.ErrorContains(t, err, "missing required field")
}

func TestFailedCheckpointAndAckLatchWithoutPublishing(t *testing.T) {
	dir := t.TempDir()
	b, _ := openTestBuffer(t, dir, testConfig())
	b.StageLine(policyLine(protectDenyMessage, ``), time.Time{})
	before := cloneState(b.state)
	require.NoError(t, os.RemoveAll(dir))
	err := b.CommitCheckpoint([]byte("checkpoint"))
	require.Error(t, err)
	require.Equal(t, before, b.state, "failed checkpoint published state")
	require.Error(t, b.Err())

	dir2 := t.TempDir()
	cfg := testConfig()
	cfg.Capacity = 1
	b2, _ := openTestBuffer(t, dir2, cfg)
	commitPolicies(t, b2, 3)
	before = cloneState(b2.state)
	require.NoError(t, os.RemoveAll(dir2))
	response, err := b2.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: b2.state.Epoch, SinceSeq: 1})
	require.Nil(t, response)
	require.Error(t, err)
	require.True(t, equalState(before, b2.state), "failed acknowledgement published")
	require.Zero(t, b2.Counters()["retention_gap_reports"], "failed pulls do not increment gap reports")
	require.Error(t, b2.Err())
}

func TestPostRenameSyncFailureLatchesAndNeverOverwritesUncertainState(t *testing.T) {
	dir := t.TempDir()
	b, _ := openTestBuffer(t, dir, testConfig())
	b.StageLine(policyLine(protectDenyMessage, ``), time.Time{})
	b.syncDir = func(string) error { return errors.New("injected directory sync failure") }
	err := b.CommitCheckpoint([]byte("offset"))
	require.ErrorContains(t, err, "durability uncertain")
	require.Zero(t, b.state.NewestSeq, "uncertain state is not published in memory")
	require.Error(t, b.Err())
	require.Error(
		t,
		b.CommitCheckpoint([]byte("later offset")),
		"fatal state cannot overwrite the potentially committed rename",
	)
	persisted, err := os.ReadFile(filepath.Join(dir, stateFileName))
	require.NoError(t, err)
	var envelope diskEnvelope
	require.NoError(t, json.Unmarshal(persisted, &envelope))
	var disk diskState
	require.NoError(t, json.Unmarshal(envelope.State, &disk))
	require.Equal(t, uint64(1), disk.NewestSeq, "rename may already have committed candidate data")
}

func TestNoChangeCheckpointSuppressesSnapshotWriteButRawInputCommits(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	commitPolicies(t, b, 20)
	writes := 0
	b.syncDir = func(path string) error {
		writes++
		return syncStateDirectory(path)
	}
	require.NoError(t, b.Sweep())
	require.NoError(t, b.CommitCheckpoint([]byte("opaque stanza offsets")))
	require.Zero(t, writes)
	b.StageLine([]byte(`{"message":"ordinary ignored log"}`), time.Time{})
	require.NoError(t, b.CommitCheckpoint([]byte("opaque stanza offsets")))
	require.Equal(t, 1, writes, "raw activity is part of the same event/checkpoint transaction")
	require.NoError(t, b.CommitCheckpoint([]byte("opaque stanza offsets")))
	require.Equal(t, 1, writes, "identical no-change polls do not rewrite state")
}

func TestIdleExpiryPersistsWithoutNewIngress(t *testing.T) {
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	cfg := testConfig()
	cfg.MaxAge = time.Minute
	cfg.Now = func() time.Time { return now }
	dir := t.TempDir()
	b, _ := openTestBuffer(t, dir, cfg)
	commitPolicies(t, b, 1)
	now = now.Add(2 * time.Minute)
	require.NoError(t, b.Sweep())
	require.Empty(t, b.state.Events)
	require.Equal(t, uint64(1), b.state.DroppedEvents)
	require.NoError(t, b.Close())
	reopened, _, err := Open(dir, cfg)
	require.NoError(t, err)
	require.Empty(t, reopened.state.Events)
	require.Equal(t, uint64(1), reopened.state.DroppedEvents)
	gap, err := reopened.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: reopened.state.Epoch})
	require.NoError(t, err)
	require.True(t, gap.GetGap())
	require.Equal(t, uint64(1), gap.GetDropped())
	cleared, err := reopened.PullEvents(
		context.Background(),
		&agentv1.PullEventsRequest{Epoch: reopened.state.Epoch, SinceSeq: 1},
	)
	require.NoError(t, err)
	require.False(t, cleared.GetGap())
	require.Zero(t, cleared.GetDropped())
	require.NoError(t, reopened.Close())
}

func TestStatusReadOnlyAndConcurrentAccess(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	commitPolicies(t, b, 20)
	beforeAck := b.state.AckedSeq
	epoch := b.state.Epoch
	_, err := b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, beforeAck, b.state.AckedSeq)

	var wg sync.WaitGroup
	for worker := range 6 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for range 30 {
				switch worker % 3 {
				case 0:
					b.StageLine(policyLine(protectDenyMessage, ``), time.Time{})
					_ = b.CommitCheckpoint(nil)
				case 1:
					_, _ = b.PullEvents(context.Background(), &agentv1.PullEventsRequest{Epoch: epoch})
				case 2:
					_, _ = b.GetStatus(context.Background(), &agentv1.GetStatusRequest{})
				}
			}
		}(worker)
	}
	wg.Wait()
}

func TestMalformedNestedStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	b, _ := openTestBuffer(t, dir, testConfig())
	commitPolicies(t, b, 1)
	b.state.Events[0].Payload = []byte("not protobuf")
	// Use direct persistence to model a state written by another version or
	// interrupted external tool; loading validates every nested event payload.
	require.NoError(t, b.persist(b.state))
	require.NoError(t, b.Close())
	_, _, err := Open(dir, testConfig())
	require.ErrorContains(t, err, "decode event")
}

func TestParserPreservesOptionalFieldsAndTimestamp(t *testing.T) {
	record := map[string]any{
		"message": learnMessage, "direction": "inbound", "src.identity": "spiffe://source",
		"dst.identity": "spiffe://destination", "dst.workload": "", "dst.namespace": "ns",
		"dst.hbone_addr": "10.0.0.2:08080",
	}
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	line := append([]byte("2026-11-02T00:00:00.123Z stdout F "), encoded...)
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	b.StageLine(line, time.Time{})
	require.NoError(t, b.CommitCheckpoint(nil))
	resp, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	learn := resp.GetEvents()[0].GetLearn()
	require.NotNil(t, learn.DestinationName)
	require.Empty(t, learn.GetDestinationName())
	require.NotNil(t, learn.DestinationNamespace)
	require.Equal(t, "08080", learn.GetDestinationPort())
	require.NotNil(t, resp.GetEvents()[0].GetObservedAt())
	require.Equal(t, encoded, resp.GetEvents()[0].GetRawRecord())

	badTimestamp := []byte(strings.Replace(string(line), "2026-11-02T00:00:00.123Z", "invalid", 1))
	event, observed, classified := parseLine(badTimestamp)
	require.True(t, classified)
	require.Nil(t, observed)
	require.NotNil(t, event)
	_, _, classified = parseLine(policyLine(monitorDenyMessage, ``))
	require.True(t, classified, "both monitor and protect classifications are represented")

	hugePort := strings.Repeat("9", 100)
	hugeRecord := map[string]any{
		"message": learnMessage, "direction": "inbound", "src.identity": "spiffe://source",
		"dst.identity": "spiffe://destination", "dst.hbone_addr": "10.0.0.2:" + hugePort,
	}
	hugeJSON, marshalErr := json.Marshal(hugeRecord)
	require.NoError(t, marshalErr)
	hugeLine := append([]byte("2026-11-02T00:00:00Z stdout F "), hugeJSON...)
	hugeEvent, _, hugeClassified := parseLine(hugeLine)
	require.True(t, hugeClassified)
	require.Equal(t, hugePort, hugeEvent.GetLearn().GetDestinationPort())
}

func TestParserRejectedRecordsCountReceivedWithoutSequence(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	lines := [][]byte{
		[]byte(`2026-11-02T00:00:00Z stdout F {"message":"deny policy match","policy":123}`),
		[]byte("2026-11-02T00:00:00Z stdin F {\"message\":\"deny policy match\"}"),
		[]byte(`{"message":"deny policy match"}`),
		[]byte("2026-11-02T00:00:00Z stdout F {invalid json}"),
		policyLine("ordinary ignored message", ``),
	}
	for _, line := range lines {
		b.StageLine(line, time.Time{})
	}
	valid := policyLine(protectDenyMessage, ``)
	b.StageLine(valid, time.Time{})
	require.NoError(t, b.CommitCheckpoint([]byte("parser-offset")))
	require.Equal(t, uint64(len(lines)+1), b.state.ReceivedEvents)
	require.Equal(t, uint64(1), b.state.NewestSeq)
	response, err := b.PullEvents(context.Background(), &agentv1.PullEventsRequest{})
	require.NoError(t, err)
	require.Len(t, response.GetEvents(), 1)
	require.JSONEq(t,
		`{"message":"deny policy match","proxy":{"wl":"ns/pod"},"inbound":{"peer":"10.0.0.1:1234"}}`,
		string(response.GetEvents()[0].GetRawRecord()),
	)
}

func BenchmarkCommit10KBacklog(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		b.StopTimer()
		dir := b.TempDir()
		buffer, _, err := Open(dir, Config{Capacity: DefaultCapacity, MaxAge: DefaultMaxAge, MaxBytes: DefaultMaxBytes})
		if err != nil {
			b.Fatal(err)
		}
		for range DefaultCapacity {
			buffer.StageLine(policyLine(protectDenyMessage, `,"policy":"ns/deny"`), time.Now())
		}
		b.StartTimer()
		commitErr := buffer.CommitCheckpoint([]byte("benchmark checkpoint"))
		if commitErr != nil {
			b.Fatal(commitErr)
		}
		b.StopTimer()
		info, err := os.Stat(filepath.Join(dir, stateFileName))
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(info.Size()), "snapshot-B")
		closeErr := buffer.Close()
		if closeErr != nil {
			b.Fatal(closeErr)
		}
	}
}

func TestUnexpectedBatchShapeIsRejected(t *testing.T) {
	b, _ := openTestBuffer(t, t.TempDir(), testConfig())
	err := b.Batch(context.Background(), nil)
	require.Error(t, err)
	require.Error(t, b.Err(), "unexpected storage operations must be visible to agent shutdown")
}
