package scraper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	retry "github.com/avast/retry-go/v4"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/kubewarden/network-enforcer/internal/ringbuf"
)

func isContextCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func runStreamWithReconnect(
	ctx context.Context,
	logger *slog.Logger,
	name string,
	stream func(context.Context, *bool) error,
) error {
	const (
		reconnectMinBackoff         = 1 * time.Second
		reconnectMaxBackoff         = 30 * time.Second
		maxConsecutiveFailures uint = 5
	)
	for {
		successfulConnection := false
		err := retry.Do(
			func() error {
				return stream(ctx, &successfulConnection)
			},
			retry.Context(ctx),
			retry.Attempts(maxConsecutiveFailures),
			retry.Delay(reconnectMinBackoff),
			retry.DelayType(retry.BackOffDelay),
			retry.MaxDelay(reconnectMaxBackoff),
			retry.RetryIf(func(err error) bool {
				if isContextCancellation(err) ||
					successfulConnection {
					// every time we stop a successful stream, we will do a fresh retry
					return false
				}
				return true
			}),
			retry.OnRetry(func(n uint, retryErr error) {
				logger.WarnContext(ctx, name+" scraper stream failed before processing flows, retrying",
					"attempt", n+1,
					"maxAttempts", maxConsecutiveFailures,
					"error", retryErr,
				)
			}),
		)
		if isContextCancellation(err) || ctx.Err() != nil {
			break
		}
		if !successfulConnection {
			return fmt.Errorf("%s scraper stopped after %d consecutive failures: %w",
				strings.ToLower(name), maxConsecutiveFailures, err)
		}
		// The stream was interrupted after a successful connection: back off
		logger.WarnContext(ctx, name+" scraper stream connection was interrupted, retrying",
			"error", err,
		)
		select {
		case <-ctx.Done():
			logger.InfoContext(ctx, name+" scraper shutting down due to context cancel")
			return nil
		case <-time.After(reconnectMinBackoff):
			continue
		}
	}
	logger.InfoContext(ctx, name+" scraper shutting down due to context cancel")
	//nolint:nilerr // ignore context cancellation errors
	return nil
}

func marshalFlow(flow any) (json.RawMessage, error) {
	if msg, ok := flow.(proto.Message); ok {
		raw, err := protojson.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal proto flow: %w", err)
		}
		return raw, nil
	}

	raw, err := json.Marshal(flow)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal flow: %w", err)
	}
	return raw, nil
}

func dumpFlow(
	ctx context.Context,
	logger *slog.Logger,
	buf *ringbuf.Buffer[json.RawMessage],
	record any,
) {
	if buf == nil {
		return
	}

	marshaled, err := marshalFlow(record)
	if err != nil {
		logger.WarnContext(ctx, "Failed to marshal flow debug data", "error", err)
		return
	}

	// for now we don't keep track of the drops since this buffer is supposed to drop if nobody is reading from it
	_ = buf.Record(marshaled)
}
