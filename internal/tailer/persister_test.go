package tailer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilePersister(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, path string)
		check func(t *testing.T, p *filePersister)
	}{
		{
			name:  "missing file starts empty",
			setup: func(_ *testing.T, _ string) {},
			check: func(t *testing.T, p *filePersister) {
				got, err := p.Get(context.Background(), "k")
				require.NoError(t, err)
				assert.Nil(t, got)
			},
		},
		{
			name: "corrupt file starts empty and is not fatal",
			setup: func(t *testing.T, path string) {
				require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
			},
			check: func(t *testing.T, p *filePersister) {
				got, err := p.Get(context.Background(), "k")
				require.NoError(t, err)
				assert.Nil(t, got)
			},
		},
		{
			name: "existing file loads values",
			setup: func(t *testing.T, path string) {
				raw, err := json.Marshal(map[string][]byte{"k": []byte("v")})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0o600))
			},
			check: func(t *testing.T, p *filePersister) {
				got, err := p.Get(context.Background(), "k")
				require.NoError(t, err)
				assert.Equal(t, []byte("v"), got)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			c.setup(t, path)
			p, err := newFilePersister(path)
			require.NoError(t, err)
			c.check(t, p)
		})
	}
}

func TestFilePersisterSetReloadAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	p, err := newFilePersister(path)
	require.NoError(t, err)
	require.NoError(t, p.Set(context.Background(), "k", []byte("v")))

	// The written file is valid JSON and no temp file is left behind.
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var data map[string][]byte
	require.NoError(t, json.Unmarshal(raw, &data))
	assert.Equal(t, []byte("v"), data["k"])
	_, err = os.Stat(path + ".tmp")
	assert.True(t, os.IsNotExist(err))

	// A fresh persister reads the saved value back.
	p2, err := newFilePersister(path)
	require.NoError(t, err)
	got, err := p2.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}
