package agentbuffer

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/network-enforcer/internal/tailer"
)

func TestTailerFailsClosedOnMalformedNestedCheckpoint(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	b, _ := openTestBuffer(t, stateDir, testConfig())
	require.NoError(t, b.CommitCheckpoint([]byte("malformed checkpoint protobuf")))
	require.NoError(t, b.Close())

	reopened, recovered, err := Open(stateDir, testConfig())
	require.NoError(t, err)
	require.True(t, recovered)
	before := cloneState(reopened.state)
	tl, err := tailer.New(tailer.Config{
		Include: []string{filepath.Join(root, "*.log")}, CheckpointStore: reopened,
	}, func(tailer.Line) {})
	require.NoError(t, err)
	err = tl.Start()
	require.Error(t, err, "agent seam must not reset malformed nested offsets")
	require.True(t, equalState(before, reopened.state))
	require.NoError(t, reopened.Close())
}
