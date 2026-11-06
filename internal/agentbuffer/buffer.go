// Package agentbuffer implements the agent's durable, bounded event buffer.
package agentbuffer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	agentv1 "github.com/kubewarden/network-enforcer/proto/agent/v1"
)

const (
	DefaultCapacity       = 10_000
	DefaultMaxAge         = 5 * time.Minute
	DefaultMaxBytes       = 16 << 20
	MaxEventBytes         = 1 << 20
	MaxResponseBytes      = 4 << 20
	DefaultPullLimit      = 1_000
	MaximumPullLimit      = 10_000
	stateVersion          = 1
	stateFileName         = "agent-state.json"
	lockFileName          = "agent-state.lock"
	maxStateFileBytes     = 32 << 20
	knownFilesKey         = "knownFiles"
	privateFileMode       = 0o600
	responseEventsFieldNo = 4
)

var errSequenceExhausted = errors.New("agent buffer sequence space exhausted")

// Config bounds both retained events and uncommitted records staged by one tailer poll.
type Config struct {
	Capacity int
	MaxAge   time.Duration
	MaxBytes int
	Now      func() time.Time
}

func (c Config) defaults() (Config, error) {
	if c.Capacity == 0 {
		c.Capacity = DefaultCapacity
	}
	if c.MaxAge == 0 {
		c.MaxAge = DefaultMaxAge
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.Capacity < 1 || c.MaxAge <= 0 || c.MaxBytes < MaxEventBytes {
		return c, errors.New("agent buffer capacity, age, or byte limit is invalid")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}

type storedEvent struct {
	Payload    []byte `json:"payload"`
	EnqueuedAt int64  `json:"enqueuedAt"`
}

type diskState struct {
	Version        int           `json:"version"`
	Epoch          string        `json:"epoch"`
	NewestSeq      uint64        `json:"newestSeq"`
	AckedSeq       uint64        `json:"ackedSeq"`
	ReceivedEvents uint64        `json:"receivedEvents"`
	DroppedEvents  uint64        `json:"droppedEvents"`
	RejectedEvents uint64        `json:"rejectedEvents"`
	EpochResets    uint64        `json:"epochResets"`
	Events         []storedEvent `json:"events"`
	KnownFiles     []byte        `json:"knownFiles"`
}

type diskEnvelope struct {
	State    json.RawMessage `json:"state"`
	Checksum string          `json:"sha256"`
}

type pendingEvent struct {
	seq        uint64
	payload    []byte
	enqueuedAt time.Time
}

// Buffer owns all API reads/writes for one durable agent-state directory.
// Calls are safe to make concurrently with tailer callbacks.
type Buffer struct {
	agentv1.UnimplementedAgentServiceServer

	mu                  sync.Mutex
	cfg                 Config
	path                string
	lock                *os.File
	syncDir             func(string) error
	state               diskState
	pending             []pendingEvent
	pendingSize         int
	pendingSeq          uint64
	pendingIn           uint64
	pendingDrop         uint64
	pendingBad          uint64
	fatal               error
	currentLogs         []string
	retentionGapReports uint64
	epochGapReports     uint64
}

// Open loads or creates a buffer in dir. A missing state file creates and durably
// initializes a fresh epoch. Existing state is never silently reset on load errors.
// The bool reports whether the state was recovered and therefore tailing must replay
// from the beginning even if the checkpoint is empty.
func Open(dir string, cfg Config) (*Buffer, bool, error) {
	cfg, configErr := cfg.defaults()
	if configErr != nil {
		return nil, false, configErr
	}
	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		return nil, false, fmt.Errorf("create agent state directory: %w", mkdirErr)
	}
	lockPath := filepath.Join(dir, lockFileName)
	_, markerErr := os.Lstat(lockPath)
	markerExisted := markerErr == nil
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return nil, false, fmt.Errorf("inspect agent state lock: %w", markerErr)
	}
	lock, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if lockErr != nil {
		return nil, false, fmt.Errorf("open agent state lock: %w", lockErr)
	}
	if flockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); flockErr != nil {
		_ = lock.Close()
		return nil, false, fmt.Errorf("lock agent state directory: %w", flockErr)
	}
	if cleanupErr := cleanStaleTemps(dir); cleanupErr != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
		return nil, false, fmt.Errorf("clean stale agent state temporaries: %w", cleanupErr)
	}
	b := &Buffer{cfg: cfg, path: filepath.Join(dir, stateFileName), lock: lock, syncDir: syncStateDirectory}
	state, recovered, loadErr := b.load()
	if loadErr != nil {
		_ = b.Close()
		return nil, false, loadErr
	}
	b.state = state
	if !recovered {
		fresh, freshErr := freshState()
		if freshErr == nil {
			freshErr = b.persist(fresh)
		}
		if freshErr != nil {
			_ = b.Close()
			return nil, false, fmt.Errorf("initialize agent state: %w", freshErr)
		}
		b.state = fresh
	}
	return b, recovered || markerExisted, nil
}

func freshState() (diskState, error) {
	epoch, err := randomEpoch()
	if err != nil {
		return diskState{}, err
	}
	return diskState{Version: stateVersion, Epoch: epoch, EpochResets: 1, Events: []storedEvent{}}, nil
}

func (b *Buffer) load() (diskState, bool, error) {
	file, openErr := os.Open(b.path)
	if openErr != nil {
		if errors.Is(openErr, os.ErrNotExist) {
			if _, statErr := os.Lstat(b.path); errors.Is(statErr, os.ErrNotExist) {
				return diskState{}, false, nil
			} else if statErr != nil {
				return diskState{}, false, fmt.Errorf("inspect agent state path: %w", statErr)
			}
		}
		return diskState{}, false, fmt.Errorf("read agent state: %w", openErr)
	}
	defer file.Close()
	info, statErr := file.Stat()
	if statErr != nil {
		return diskState{}, false, fmt.Errorf("stat agent state: %w", statErr)
	}
	if info.Size() > maxStateFileBytes {
		return diskState{}, false, fmt.Errorf("agent state exceeds %d bytes", maxStateFileBytes)
	}
	raw, readErr := io.ReadAll(file)
	if readErr != nil {
		return diskState{}, false, fmt.Errorf("read agent state: %w", readErr)
	}
	if len(raw) > maxStateFileBytes {
		return diskState{}, false, fmt.Errorf("agent state exceeds %d bytes", maxStateFileBytes)
	}
	state, decodeErr := decodeStateEnvelope(raw, b.cfg)
	if decodeErr != nil {
		return diskState{}, false, decodeErr
	}
	return state, true, nil
}

func validateState(s diskState, cfg Config) error {
	if s.Version != stateVersion {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	if s.Epoch == "" || len(s.Epoch) > 128 {
		return errors.New("invalid epoch")
	}
	if s.AckedSeq > s.NewestSeq {
		return errors.New("acknowledgement exceeds newest sequence")
	}
	if s.Events == nil {
		return errors.New("event list is missing")
	}
	if len(s.Events) > cfg.Capacity {
		return errors.New("retained event count exceeds configured capacity")
	}
	bytes, err := validateRetainedEvents(s)
	if err != nil {
		return err
	}
	if bytes > cfg.MaxBytes {
		return errors.New("retained event bytes exceed configured limit")
	}
	return nil
}

func validateRetainedEvents(s diskState) (int, error) {
	var totalBytes int
	var previous uint64
	for index, stored := range s.Events {
		event := &agentv1.Event{}
		if err := proto.Unmarshal(stored.Payload, event); err != nil {
			return 0, fmt.Errorf("decode event %d: %w", index, err)
		}
		if err := validateRetainedEvent(event, stored.Payload, index, previous, s.NewestSeq); err != nil {
			return 0, err
		}
		totalBytes += len(stored.Payload)
		previous = event.GetSeq()
	}
	if len(s.Events) == 0 {
		return totalBytes, nil
	}
	first := &agentv1.Event{}
	if err := proto.Unmarshal(s.Events[0].Payload, first); err != nil {
		return 0, err
	}
	if first.GetSeq() != s.NewestSeq-uint64(len(s.Events))+1 {
		return 0, errors.New("retained events are not the newest contiguous sequence range")
	}
	return totalBytes, nil
}

func validateRetainedEvent(event *agentv1.Event, payload []byte, index int, previous, newest uint64) error {
	seq := event.GetSeq()
	if seq == 0 || (index > 0 && seq != previous+1) || seq > newest {
		return fmt.Errorf("event %d has inconsistent sequence", index)
	}
	if event.Kind == nil {
		return fmt.Errorf("event %d has no kind", index)
	}
	if len(payload) > MaxEventBytes {
		return fmt.Errorf("event %d exceeds event size limit", index)
	}
	return nil
}

func (b *Buffer) persist(s diskState) error {
	raw, marshalErr := encodeStateEnvelope(s)
	if marshalErr != nil {
		return marshalErr
	}
	if len(raw) > maxStateFileBytes {
		return fmt.Errorf("serialized agent state exceeds %d bytes", maxStateFileBytes)
	}
	tmp, createErr := os.CreateTemp(filepath.Dir(b.path), ".agent-state-*")
	if createErr != nil {
		return createErr
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if chmodErr := tmp.Chmod(privateFileMode); chmodErr != nil {
		_ = tmp.Close()
		return chmodErr
	}
	n, writeErr := tmp.Write(raw)
	if writeErr != nil {
		_ = tmp.Close()
		return writeErr
	}
	if n != len(raw) {
		_ = tmp.Close()
		return io.ErrShortWrite
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		return syncErr
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return closeErr
	}
	if renameErr := os.Rename(tmpName, b.path); renameErr != nil {
		return renameErr
	}
	if dirSyncErr := b.syncDir(filepath.Dir(b.path)); dirSyncErr != nil {
		return fmt.Errorf("sync state directory after rename (durability uncertain): %w", dirSyncErr)
	}
	return nil
}

func (b *Buffer) failLocked(err error) error {
	if b.fatal == nil {
		b.fatal = err
	}
	return b.fatal
}

func (b *Buffer) incrementPendingBadLocked() {
	if b.pendingBad == math.MaxUint64 {
		_ = b.failLocked(errSequenceExhausted)
		return
	}
	b.pendingBad++
}

func (b *Buffer) commitLocked(candidate diskState) error {
	if err := b.persist(candidate); err != nil {
		return b.failLocked(fmt.Errorf("persist agent state: %w", err))
	}
	b.state = candidate
	return nil
}

// StageLine records raw tailer activity and, if classified, stages an immutable event.
// All changes become visible only when the tailer's knownFiles checkpoint commits.
func (b *Buffer) StageLine(raw []byte, readAt time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fatal != nil {
		return
	}
	if b.pendingIn == math.MaxUint64 || b.state.ReceivedEvents > math.MaxUint64-b.pendingIn-1 {
		_ = b.failLocked(errSequenceExhausted)
		return
	}
	b.pendingIn++
	event, observedAt, classified := parseLine(raw)
	if !classified {
		return
	}
	event.ObservedAt = observedAt
	payload, err := proto.Marshal(event)
	if err != nil || len(payload) > MaxEventBytes {
		b.incrementPendingBadLocked()
		return
	}
	if b.state.NewestSeq > math.MaxUint64-b.pendingSeq-1 {
		_ = b.failLocked(errSequenceExhausted)
		return
	}
	seq := b.state.NewestSeq + b.pendingSeq + 1
	event.Seq = seq
	payload, err = proto.Marshal(event)
	if err != nil {
		b.incrementPendingBadLocked()
		return
	}
	if len(payload) > MaxEventBytes {
		b.incrementPendingBadLocked()
		return
	}
	enqueuedAt := readAt
	if enqueuedAt.IsZero() {
		enqueuedAt = b.cfg.Now()
	}
	pending := pendingEvent{seq: seq, payload: payload, enqueuedAt: enqueuedAt}
	b.pendingSeq++
	b.pending = append(b.pending, pending)
	b.pendingSize += len(pending.payload)
	for len(b.pending) > b.cfg.Capacity || b.pendingSize > b.cfg.MaxBytes {
		if b.pendingDrop == math.MaxUint64 {
			_ = b.failLocked(errSequenceExhausted)
			return
		}
		b.pendingDrop++
		b.pendingSize -= len(b.pending[0].payload)
		b.pending[0] = pendingEvent{}
		b.pending = b.pending[1:]
	}
}

// CommitCheckpoint atomically publishes staged events, counters and the exact stanza
// knownFiles checkpoint. It is called by fileconsumer's Batch after line callbacks.
func (b *Buffer) CommitCheckpoint(checkpoint []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fatal != nil {
		return b.fatal
	}
	candidate := cloneState(b.state)
	if candidate.ReceivedEvents > math.MaxUint64-b.pendingIn ||
		candidate.DroppedEvents > math.MaxUint64-b.pendingDrop ||
		candidate.RejectedEvents > math.MaxUint64-b.pendingBad {
		return b.failLocked(errSequenceExhausted)
	}
	candidate.ReceivedEvents += b.pendingIn
	candidate.DroppedEvents += b.pendingDrop
	candidate.RejectedEvents += b.pendingBad
	if candidate.NewestSeq > math.MaxUint64-b.pendingSeq {
		return b.failLocked(errSequenceExhausted)
	}
	candidate.NewestSeq += b.pendingSeq
	candidate.KnownFiles = append([]byte(nil), checkpoint...)
	if b.pendingDrop > 0 {
		if err := dropCommittedForPendingGap(&candidate); err != nil {
			return b.failLocked(err)
		}
	}
	for _, pending := range b.pending {
		candidate.Events = append(candidate.Events, storedEvent{
			Payload:    append([]byte(nil), pending.payload...),
			EnqueuedAt: pending.enqueuedAt.UnixNano(),
		})
	}
	if err := b.retainLocked(&candidate, b.cfg.Now()); err != nil {
		return b.failLocked(err)
	}
	if !equalState(candidate, b.state) {
		if err := b.commitLocked(candidate); err != nil {
			return err
		}
	}
	b.pending = nil
	b.pendingSize = 0
	b.pendingSeq = 0
	b.pendingIn = 0
	b.pendingDrop = 0
	b.pendingBad = 0
	return nil
}

func cloneState(s diskState) diskState {
	if s.Events != nil {
		events := make([]storedEvent, len(s.Events))
		copy(events, s.Events)
		s.Events = events
	}
	if s.KnownFiles != nil {
		s.KnownFiles = append([]byte{}, s.KnownFiles...)
	}
	return s
}

func dropCommittedForPendingGap(s *diskState) error {
	for i, stored := range s.Events {
		event := &agentv1.Event{}
		if err := proto.Unmarshal(stored.Payload, event); err != nil {
			return fmt.Errorf("decode committed event before pending gap: %w", err)
		}
		if event.GetSeq() > s.AckedSeq {
			if s.DroppedEvents == math.MaxUint64 {
				return errSequenceExhausted
			}
			s.DroppedEvents++
		}
		s.Events[i] = storedEvent{}
	}
	s.Events = s.Events[:0]
	return nil
}

func (b *Buffer) retainLocked(s *diskState, now time.Time) error {
	for len(s.Events) > 0 {
		event := &agentv1.Event{}
		if err := proto.Unmarshal(s.Events[0].Payload, event); err != nil {
			return fmt.Errorf("decode retained event: %w", err)
		}
		if now.Sub(time.Unix(0, s.Events[0].EnqueuedAt)) < b.cfg.MaxAge {
			break
		}
		if event.GetSeq() > s.AckedSeq {
			if s.DroppedEvents == math.MaxUint64 {
				return errSequenceExhausted
			}
			s.DroppedEvents++
		}
		s.Events[0] = storedEvent{}
		s.Events = s.Events[1:]
	}
	var bytes int
	for _, event := range s.Events {
		bytes += len(event.Payload)
	}
	for len(s.Events) > b.cfg.Capacity || bytes > b.cfg.MaxBytes {
		first := &agentv1.Event{}
		if err := proto.Unmarshal(s.Events[0].Payload, first); err != nil {
			return err
		}
		if first.GetSeq() > s.AckedSeq {
			if s.DroppedEvents == math.MaxUint64 {
				return errSequenceExhausted
			}
			s.DroppedEvents++
		}
		bytes -= len(s.Events[0].Payload)
		s.Events[0] = storedEvent{}
		s.Events = s.Events[1:]
	}
	return nil
}

// Sweep expires retained events during idle periods and durably records resulting drops.
func (b *Buffer) Sweep() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fatal != nil {
		return b.fatal
	}
	candidate := cloneState(b.state)
	beforeDropped := candidate.DroppedEvents
	beforeLen := len(candidate.Events)
	if err := b.retainLocked(&candidate, b.cfg.Now()); err != nil {
		return b.failLocked(err)
	}
	if candidate.DroppedEvents != beforeDropped || len(candidate.Events) != beforeLen {
		return b.commitLocked(candidate)
	}
	return nil
}

// PullEvents implements the transport-independent agent pull contract.
func (b *Buffer) PullEvents(_ context.Context, req *agentv1.PullEventsRequest) (*agentv1.PullEventsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit := req.GetLimit()
	if limit == 0 {
		limit = DefaultPullLimit
	}
	if limit > MaximumPullLimit || (req.GetEpoch() == "" && req.GetSinceSeq() != 0) {
		return nil, status.Error(codes.InvalidArgument, "invalid limit or bootstrap cursor")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fatal != nil {
		return nil, status.Error(codes.Internal, b.fatal.Error())
	}
	return b.pullLocked(req, limit)
}

func (b *Buffer) pullLocked(req *agentv1.PullEventsRequest, limit uint32) (*agentv1.PullEventsResponse, error) {
	mismatch := req.GetEpoch() != "" && req.GetEpoch() != b.state.Epoch
	if !mismatch && req.GetEpoch() != "" && req.GetSinceSeq() > b.state.NewestSeq {
		return nil, status.Error(codes.InvalidArgument, "cursor exceeds newest sequence")
	}
	candidate := cloneState(b.state)
	if !mismatch && req.GetEpoch() != "" && req.GetSinceSeq() > candidate.AckedSeq {
		candidate.AckedSeq = req.GetSinceSeq()
	}
	if retainErr := b.retainLocked(&candidate, b.cfg.Now()); retainErr != nil {
		return nil, status.Error(codes.Internal, retainErr.Error())
	}
	response, responseErr := buildResponse(candidate, mismatch, limit)
	if responseErr != nil {
		return nil, status.Error(codes.ResourceExhausted, responseErr.Error())
	}
	if !equalState(candidate, b.state) {
		if persistErr := b.commitLocked(candidate); persistErr != nil {
			return nil, status.Error(codes.Internal, persistErr.Error())
		}
	}
	if mismatch && b.epochGapReports < math.MaxUint64 {
		b.epochGapReports++
	}
	if response.GetDropped() > 0 && b.retentionGapReports < math.MaxUint64 {
		b.retentionGapReports++
	}
	response.AckedSeq = candidate.AckedSeq
	return response, nil
}

func buildResponse(s diskState, mismatch bool, limit uint32) (*agentv1.PullEventsResponse, error) {
	resp := &agentv1.PullEventsResponse{
		Epoch: s.Epoch, AckedSeq: s.AckedSeq, NewestSeq: s.NewestSeq, Gap: mismatch,
	}
	var boundary uint64
	if len(s.Events) > 0 {
		first := &agentv1.Event{}
		if err := proto.Unmarshal(s.Events[0].Payload, first); err != nil {
			return nil, fmt.Errorf("decode retained event: %w", err)
		}
		boundary = first.GetSeq() - 1
	} else {
		boundary = s.NewestSeq
	}
	if boundary > s.AckedSeq {
		resp.Dropped = boundary - s.AckedSeq
	}
	if resp.GetDropped() > 0 {
		resp.Gap = true
	}
	size := proto.Size(resp)
	// PullEvents validates the caller's limit against MaximumPullLimit before this helper.
	// #nosec G115 -- the bounded uint32 limit safely fits a platform int.
	limitCount := int(limit)
	for _, stored := range s.Events {
		event := &agentv1.Event{}
		if err := proto.Unmarshal(stored.Payload, event); err != nil {
			return nil, fmt.Errorf("decode retained event: %w", err)
		}
		if event.GetSeq() <= s.AckedSeq {
			continue
		}
		if len(resp.GetEvents()) >= limitCount {
			break
		}
		eventSize := proto.Size(event)
		// Stored events are validated against MaxEventBytes on ingress and load.
		// #nosec G115 -- proto.Size is nonnegative and bounded by MaxEventBytes.
		fieldSize := protowire.SizeTag(responseEventsFieldNo) + protowire.SizeVarint(uint64(eventSize)) + eventSize
		if size+fieldSize > MaxResponseBytes {
			if len(resp.GetEvents()) == 0 {
				return nil, errors.New("next event exceeds response byte budget")
			}
			break
		}
		resp.Events = append(resp.Events, event)
		size += fieldSize
	}
	return resp, nil
}

// GetStatus returns a coherent read-only cursor snapshot, after durable idle expiry.
func (b *Buffer) GetStatus(_ context.Context, _ *agentv1.GetStatusRequest) (*agentv1.GetStatusResponse, error) {
	if err := b.Sweep(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fatal != nil {
		return nil, status.Error(codes.Internal, b.fatal.Error())
	}
	out := &agentv1.GetStatusResponse{
		Epoch: b.state.Epoch, AckedSeq: b.state.AckedSeq, NewestSeq: b.state.NewestSeq,
		BufferedEvents: uint64(len(b.state.Events)),
		// Capacity was validated to be positive and fits the platform's int range.
		// #nosec G115 -- converting a validated positive int to uint64 is safe.
		MaxEvents: uint64(b.cfg.Capacity),
		MaxAge:    durationpb.New(b.cfg.MaxAge), DroppedEvents: b.state.DroppedEvents,
		ReceivedEvents:  b.state.ReceivedEvents,
		CurrentLogFiles: append([]string(nil), b.currentLogs...),
	}
	if len(b.state.Events) > 0 {
		oldest := &agentv1.Event{}
		if err := proto.Unmarshal(b.state.Events[0].Payload, oldest); err == nil {
			out.OldestSeq = oldest.GetSeq()
		}
	}
	return out, nil
}

// SetCurrentLogFiles records latest matcher observations; paths are not persisted because
// they describe live monitoring, not durable cursor state.
func (b *Buffer) SetCurrentLogFiles(paths []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := append([]string(nil), paths...)
	sort.Strings(out)
	out = compactStrings(out)
	b.currentLogs = out
}

const twoStrings = 2

func compactStrings(in []string) []string {
	if len(in) < twoStrings {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// Counters exposes low-cardinality counters for a future metrics adapter.
func (b *Buffer) Counters() map[string]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return map[string]uint64{
		"received_events":       b.state.ReceivedEvents,
		"dropped_events":        b.state.DroppedEvents,
		"rejected_events":       b.state.RejectedEvents,
		"retention_gap_reports": b.retentionGapReports,
		"epoch_gap_reports":     b.epochGapReports,
		"epoch_resets":          b.state.EpochResets,
	}
}

// Err reports a latched durability failure, including failures hidden by stanza's logger.
func (b *Buffer) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fatal
}

// Close releases the exclusive state-directory lock.
func (b *Buffer) Close() error {
	if b.lock == nil {
		return nil
	}
	_ = syscall.Flock(int(b.lock.Fd()), syscall.LOCK_UN)
	err := b.lock.Close()
	b.lock = nil
	return err
}

// Get returns stanza's opaque knownFiles checkpoint without interpreting it.
func (b *Buffer) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if key != knownFilesKey {
		return nil, fmt.Errorf("agent buffer: unsupported checkpoint key %q", key)
	}
	return append([]byte(nil), b.state.KnownFiles...), nil
}

func (b *Buffer) Set(_ context.Context, key string, value []byte) error {
	if key != knownFilesKey {
		return fmt.Errorf("agent buffer: unsupported checkpoint key %q", key)
	}
	return b.CommitCheckpoint(value)
}

func (b *Buffer) Delete(_ context.Context, key string) error {
	if key != knownFilesKey {
		return fmt.Errorf("agent buffer: unsupported checkpoint key %q", key)
	}
	return b.CommitCheckpoint(nil)
}

func (b *Buffer) Batch(_ context.Context, ops ...*storage.Operation) error {
	if len(ops) != 1 || ops[0] == nil || ops[0].Key != knownFilesKey || ops[0].Type != storage.Set {
		return b.latchUnsupportedBatch(ops)
	}
	return b.CommitCheckpoint(ops[0].Value)
}

func (b *Buffer) latchUnsupportedBatch(ops []*storage.Operation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failLocked(fmt.Errorf("agent buffer: expected one knownFiles Set operation, got %d operations", len(ops)))
}

var _ operator.Persister = (*Buffer)(nil)
var _ agentv1.AgentServiceServer = (*Buffer)(nil)
