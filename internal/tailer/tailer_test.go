package tailer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigApplyDefaults(t *testing.T) {
	cases := []struct {
		name         string
		in           Config
		wantPoll     time.Duration
		wantStartAt  string
		wantTruncate string
	}{
		{
			name:         "empty config gets defaults",
			in:           Config{},
			wantPoll:     defaultPollInterval,
			wantStartAt:  "end",
			wantTruncate: "read_new",
		},
		{
			name:         "set values are kept",
			in:           Config{PollInterval: time.Second, StartAt: "beginning", OnTruncate: "ignore"},
			wantPoll:     time.Second,
			wantStartAt:  "beginning",
			wantTruncate: "ignore",
		},
		{
			name:         "non-positive poll falls back to default",
			in:           Config{PollInterval: -1},
			wantPoll:     defaultPollInterval,
			wantStartAt:  "end",
			wantTruncate: "read_new",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.in
			cfg.applyDefaults()
			assert.Equal(t, c.wantPoll, cfg.PollInterval)
			assert.Equal(t, c.wantStartAt, cfg.StartAt)
			assert.Equal(t, c.wantTruncate, cfg.OnTruncate)
		})
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		h    Handler
	}{
		{name: "empty include", cfg: Config{}, h: func(Line) {}},
		{name: "nil handler", cfg: Config{Include: []string{"*.log"}}, h: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.cfg, c.h)
			require.Error(t, err)
		})
	}
}
