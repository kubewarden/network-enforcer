package agentbuffer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	uuidByteCount       = 16
	uuidHexByteCount    = uuidByteCount * 2
	uuidVersionOffset   = 6
	uuidVariantOffset   = 8
	uuidFirstGroupEnd   = 8
	uuidSecondGroupEnd  = 12
	uuidThirdGroupEnd   = 16
	uuidFourthGroupEnd  = 20
	uuidVersionMask     = 0x0f
	uuidVersionFourBits = 0x40
	uuidVariantMask     = 0x3f
	uuidRFC4122Variant  = 0x80
)

func randomEpoch() (string, error) {
	var bytes [uuidByteCount]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	bytes[uuidVersionOffset] = (bytes[uuidVersionOffset] & uuidVersionMask) | uuidVersionFourBits
	bytes[uuidVariantOffset] = (bytes[uuidVariantOffset] & uuidVariantMask) | uuidRFC4122Variant
	hexBytes := make([]byte, uuidHexByteCount)
	hex.Encode(hexBytes, bytes[:])
	return string(hexBytes[:uuidFirstGroupEnd]) + "-" + string(hexBytes[uuidFirstGroupEnd:uuidSecondGroupEnd]) + "-" +
		string(
			hexBytes[uuidSecondGroupEnd:uuidThirdGroupEnd],
		) + "-" + string(hexBytes[uuidThirdGroupEnd:uuidFourthGroupEnd]) + "-" +
		string(hexBytes[uuidFourthGroupEnd:]), nil
}

func encodeStateEnvelope(state diskState) ([]byte, error) {
	stateRaw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(stateRaw)
	envelope := diskEnvelope{State: stateRaw, Checksum: hex.EncodeToString(checksum[:])}
	return json.Marshal(envelope)
}

func decodeStateEnvelope(raw []byte, cfg Config) (diskState, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope diskEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return diskState{}, fmt.Errorf("decode agent state envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return diskState{}, errors.New("agent state envelope contains trailing JSON data")
	}
	if len(envelope.State) == 0 || bytes.Equal(bytes.TrimSpace(envelope.State), []byte("null")) {
		return diskState{}, errors.New("agent state envelope is missing state")
	}
	providedChecksum, checksumErr := hex.DecodeString(envelope.Checksum)
	if checksumErr != nil || len(providedChecksum) != sha256.Size {
		return diskState{}, errors.New("agent state envelope has an invalid checksum")
	}
	actualChecksum := sha256.Sum256(envelope.State)
	if !bytes.Equal(providedChecksum, actualChecksum[:]) {
		return diskState{}, errors.New("agent state checksum mismatch")
	}
	if fieldsErr := requireStateFields(envelope.State); fieldsErr != nil {
		return diskState{}, fieldsErr
	}
	stateDecoder := json.NewDecoder(bytes.NewReader(envelope.State))
	stateDecoder.DisallowUnknownFields()
	var state diskState
	if decodeErr := stateDecoder.Decode(&state); decodeErr != nil {
		return diskState{}, fmt.Errorf("decode agent state: %w", decodeErr)
	}
	if validationErr := validateState(state, cfg); validationErr != nil {
		return diskState{}, fmt.Errorf("validate agent state: %w", validationErr)
	}
	return state, nil
}

func requireStateFields(raw []byte) error {
	requiredFields := []string{
		"version", "epoch", "newestSeq", "ackedSeq", "receivedEvents", "droppedEvents",
		"rejectedEvents", "epochResets", "events", "knownFiles",
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("read required agent state fields: %w", err)
	}
	if fields == nil {
		return errors.New("agent state must be a JSON object")
	}
	for _, key := range requiredFields {
		value, ok := fields[key]
		if !ok {
			return fmt.Errorf("agent state is missing required field %q", key)
		}
		if key != "knownFiles" && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("agent state field %q cannot be null", key)
		}
	}
	return nil
}

func equalState(a, b diskState) bool {
	if a.Version != b.Version || a.Epoch != b.Epoch || a.NewestSeq != b.NewestSeq ||
		a.AckedSeq != b.AckedSeq || a.ReceivedEvents != b.ReceivedEvents ||
		a.DroppedEvents != b.DroppedEvents || a.RejectedEvents != b.RejectedEvents ||
		a.EpochResets != b.EpochResets || !bytes.Equal(a.KnownFiles, b.KnownFiles) || len(a.Events) != len(b.Events) {
		return false
	}
	for i := range a.Events {
		if a.Events[i].EnqueuedAt != b.Events[i].EnqueuedAt || !sameBytes(a.Events[i].Payload, b.Events[i].Payload) {
			return false
		}
	}
	return true
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return &a[0] == &b[0]
}

func cleanStaleTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if isStaleStateTemp(entry) {
			if removeErr := os.Remove(filepath.Join(dir, entry.Name())); removeErr != nil {
				return removeErr
			}
		}
	}
	return nil
}

func isStaleStateTemp(entry os.DirEntry) bool {
	return strings.HasPrefix(entry.Name(), ".agent-state-") && entry.Type().IsRegular()
}

func syncStateDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	if syncErr != nil {
		_ = dir.Close()
		return syncErr
	}
	return dir.Close()
}
