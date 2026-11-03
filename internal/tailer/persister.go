// Package tailer tails CRI container log files for the per-node agent.
// It wraps the stanza fileconsumer. It aligns the first read to the end of
// each file, survives log rotation and truncation, and checkpoints file
// offsets to disk so it resumes after a restart.
package tailer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"go.opentelemetry.io/collector/extension/xextension/storage"
)

// filePersister keeps fileconsumer checkpoints in one JSON file.
// fileconsumer calls it after each poll and at stop, so the agent resumes
// from the saved offsets after a restart. The file lives in a hostPath
// directory, so the offsets survive a pod restart.
type filePersister struct {
	mu   sync.Mutex
	path string
	data map[string][]byte
}

// newFilePersister reads the checkpoint file at path. A missing, empty or
// corrupt file starts an empty store. A corrupt file is logged, not fatal,
// so one bad file does not stop the agent.
func newFilePersister(path string) (*filePersister, error) {
	p := &filePersister{path: path, data: map[string][]byte{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return nil, err
	}
	if len(raw) == 0 {
		return p, nil
	}
	if unmarshalErr := json.Unmarshal(raw, &p.data); unmarshalErr != nil {
		slog.Default().Warn("Dropped a corrupt checkpoint file", "path", path, "err", unmarshalErr)
		p.data = map[string][]byte{}
	}
	return p, nil
}

// flush writes the store to disk through a temporary file and a rename, so a
// crash during the write does not leave a partial checkpoint file.
func (p *filePersister) flush() error {
	raw, err := json.Marshal(p.data)
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if writeErr := os.WriteFile(tmp, raw, 0o600); writeErr != nil {
		return writeErr
	}
	return os.Rename(tmp, p.path)
}

func (p *filePersister) Get(_ context.Context, k string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.data[k], nil
}

func (p *filePersister) Set(_ context.Context, k string, v []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.data[k] = v
	return p.flush()
}

func (p *filePersister) Delete(_ context.Context, k string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.data, k)
	return p.flush()
}

func (p *filePersister) Batch(_ context.Context, ops ...*storage.Operation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, op := range ops {
		switch op.Type {
		case storage.Set:
			p.data[op.Key] = op.Value
		case storage.Delete:
			delete(p.data, op.Key)
		case storage.Get:
			op.Value = p.data[op.Key]
		default:
			return fmt.Errorf("filePersister: unknown operation type %v", op.Type)
		}
	}
	return p.flush()
}
