package ocihook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	maxNotifyAttempts         = 3
	notifyRetryBackoff        = 100 * time.Millisecond
	DefaultNotifyAgentTimeout = 5 * time.Second
)

func NotifyAgent(ctx context.Context, socketPath string, req HookRequest) error {
	var d net.Dialer
	var conn net.Conn
	var err error

	if conn, err = d.DialContext(ctx, "unix", socketPath); err != nil {
		return fmt.Errorf("dial agent socket %q: %w", socketPath, err)
	}
	defer conn.Close()

	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	var resp HookResponse
	if err = json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if !resp.OK {
		if resp.Error != "" {
			return fmt.Errorf("agent: %s", resp.Error)
		}
		return errors.New("agent rejected registration")
	}
	return nil
}

func NotifyAgentWithRetry(socketPath string, req HookRequest, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var lastErr error
	for attempt := range maxNotifyAttempts {
		err := NotifyAgent(ctx, socketPath, req)
		if err == nil {
			return nil
		}
		lastErr = err

		backoff := time.Duration(attempt) * notifyRetryBackoff
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}

	return fmt.Errorf("notify agent failed after %d attempts: %w", maxNotifyAttempts, lastErr)
}
