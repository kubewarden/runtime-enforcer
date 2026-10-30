package wpgen

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingStdin returns a reader that blocks until the test ends, like a
// terminal where the user types nothing.
func blockingStdin(t *testing.T) io.Reader {
	t.Helper()

	r, w := io.Pipe()
	t.Cleanup(func() { w.Close() })
	return r
}

// waitResult waits for the result of a function that runs in a goroutine. It
// fails the test when the function does not return in time.
func waitResult[T any](t *testing.T, results <-chan T) T {
	t.Helper()

	select {
	case res := <-results:
		return res
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the read did not stop when the context was cancelled")
		var zero T
		return zero
	}
}

func TestContextReader(t *testing.T) {
	t.Parallel()

	t.Run("passes the data through", func(t *testing.T) {
		t.Parallel()

		data, err := io.ReadAll(newContextReader(t.Context(), strings.NewReader("kind: Deployment\n")))
		require.NoError(t, err)
		assert.Equal(t, "kind: Deployment\n", string(data))
	})

	t.Run("stops a blocked read when the context is cancelled", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		r := newContextReader(ctx, blockingStdin(t))

		errs := make(chan error, 1)
		go func() {
			_, err := r.Read(make([]byte, 16))
			errs <- err
		}()
		cancel()

		require.ErrorIs(t, waitResult(t, errs), context.Canceled)
	})

	t.Run("does not read after the context is cancelled", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		n, err := newContextReader(ctx, strings.NewReader("data")).Read(make([]byte, 16))
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, n)
	})
}

// TestWorkloadCmdStdinInterrupted reproduces Ctrl-C while wpgen waits for a
// manifest on standard input.
func TestWorkloadCmdStdinInterrupted(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"workload", "-"})
	cmd.SetIn(blockingStdin(t))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errs := make(chan error, 1)
	go func() { errs <- cmd.ExecuteContext(ctx) }()
	cancel()

	require.ErrorIs(t, waitResult(t, errs), context.Canceled)
}

func TestExitCode(t *testing.T) {
	t.Parallel()

	interrupted, cancel := context.WithCancelCause(t.Context())
	cancel(errors.New("interrupt signal received"))

	tests := []struct {
		name   string
		ctx    context.Context //nolint:containedctx // each row runs with its own context.
		err    error
		code   int
		stderr string
	}{
		{name: "success", ctx: t.Context(), code: 0},
		{name: "error", ctx: t.Context(), err: errors.New("no supported workload found in -"), code: 1,
			stderr: "Error: no supported workload found in -\n"},
		{
			name: "error already reported",
			ctx:  t.Context(),
			err:  &reportedError{msg: "1 allowed path is stale"},
			code: 1,
		},
		{name: "interrupted", ctx: interrupted, err: context.Canceled, code: exitInterrupted,
			stderr: "Interrupted: interrupt signal received\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stderr strings.Builder
			assert.Equal(t, tt.code, exitCode(tt.ctx, tt.err, &stderr, painter{}))
			assert.Equal(t, tt.stderr, stderr.String())
		})
	}
}
