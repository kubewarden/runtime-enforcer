package wpgen

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// blockingReader is a reader that blocks until the test ends, and reports
// the start of its first Read on started.
type blockingReader struct {
	r       io.Reader
	started chan struct{}
}

func newBlockingReader(t *testing.T) *blockingReader {
	t.Helper()

	return &blockingReader{r: blockingStdin(t), started: make(chan struct{})}
}

func (b *blockingReader) Read(p []byte) (int, error) {
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	return b.r.Read(p)
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

// waitStarted waits until the blocked read starts, so that the test cancels
// a read that is really blocked.
func waitStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the read did not start")
	}
}

// namedPipe returns the path of a new named pipe. An open of the pipe for
// reading blocks until a writer opens it, as a Read of a terminal does.
func namedPipe(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "input.fifo")
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	return path
}

// keepOpen opens the named pipe for writing, without data, so that an open
// for reading returns and a read blocks. The open uses O_RDWR, which does
// not wait for a reader on Linux.
func keepOpen(t *testing.T, pipe string) {
	t.Helper()

	w, err := os.OpenFile(pipe, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { w.Close() })
}

// controlledOpen is an open that reports its start, blocks until the test
// releases it, and then returns a regular file. The test can observe the
// closure of the file. It stands in for the open of a named pipe, which
// blocks until a writer arrives and cannot be released with certainty.
type controlledOpen struct {
	started chan struct{}
	release chan struct{}
	file    *os.File
}

func newControlledOpen(t *testing.T) *controlledOpen {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "input")
	require.NoError(t, err)
	c := &controlledOpen{started: make(chan struct{}), release: make(chan struct{}), file: f}
	t.Cleanup(func() {
		c.releaseOnce()
		_ = f.Close()
	})
	return c
}

func (c *controlledOpen) open(string) (*os.File, error) {
	close(c.started)
	<-c.release
	return c.file, nil
}

func (c *controlledOpen) releaseOnce() {
	select {
	case <-c.release:
	default:
		close(c.release)
	}
}

// closed reports if the file of the open is closed.
func (c *controlledOpen) closed() bool {
	_, err := c.file.Stat()
	return errors.Is(err, os.ErrClosed)
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
		blocking := newBlockingReader(t)
		r := newContextReader(ctx, blocking)

		errs := make(chan error, 1)
		go func() {
			_, err := r.Read(make([]byte, 16))
			errs <- err
		}()
		waitStarted(t, blocking.started)
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

func TestOpenInput(t *testing.T) {
	t.Parallel()

	t.Run("standard input", func(t *testing.T) {
		t.Parallel()

		r, err := openInput(t.Context(), stdinFile, strings.NewReader("from stdin"))
		require.NoError(t, err)
		defer r.Close()

		data, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "from stdin", string(data))
	})

	t.Run("file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "input.yaml")
		require.NoError(t, os.WriteFile(path, []byte("from file"), 0o600))

		r, err := openInput(t.Context(), path, strings.NewReader("from stdin"))
		require.NoError(t, err)

		data, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "from file", string(data))
		require.NoError(t, r.Close())
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := openInput(t.Context(), filepath.Join(t.TempDir(), "missing.yaml"), strings.NewReader(""))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("cancelled before the open", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := openInput(ctx, namedPipe(t), strings.NewReader(""))
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("cancelled during a read of a named pipe", func(t *testing.T) {
		t.Parallel()

		pipe := namedPipe(t)
		keepOpen(t, pipe)

		ctx, cancel := context.WithCancel(t.Context())
		r, err := openInput(ctx, pipe, strings.NewReader(""))
		require.NoError(t, err)
		defer r.Close()

		errs := make(chan error, 1)
		go func() {
			_, readErr := r.Read(make([]byte, 16))
			errs <- readErr
		}()
		time.Sleep(50 * time.Millisecond)
		cancel()

		require.ErrorIs(t, waitResult(t, errs), context.Canceled)
	})
}

// TestOpenFileCancelledDuringTheOpen covers the open of a named pipe, which
// blocks until a writer arrives: the caller stops at the cancellation, and
// the goroutine of the open closes the file when the open finishes later.
func TestOpenFileCancelledDuringTheOpen(t *testing.T) {
	t.Parallel()

	open := newControlledOpen(t)
	ctx, cancel := context.WithCancel(t.Context())
	errs := make(chan error, 1)
	go func() {
		_, err := openFileWith(ctx, "input", open.open)
		errs <- err
	}()
	waitStarted(t, open.started)
	cancel()
	require.ErrorIs(t, waitResult(t, errs), context.Canceled)

	// The open finishes after the caller left. Nobody else can close the
	// file, so the goroutine of the open must do it.
	require.False(t, open.closed(), "the file is still open while the open blocks")
	open.releaseOnce()
	require.Eventually(t, open.closed, 10*time.Second, 10*time.Millisecond,
		"the late open left the file open")
}

// TestOpenFileReturnsTheFile is the control case of the test above: without
// a cancellation, the caller gets the file and owns it.
func TestOpenFileReturnsTheFile(t *testing.T) {
	t.Parallel()

	open := newControlledOpen(t)
	open.releaseOnce()
	f, err := openFileWith(t.Context(), "input", open.open)
	require.NoError(t, err)
	require.Same(t, open.file, f)
	require.False(t, open.closed(), "the caller owns the file")
}

// TestWorkloadCmdStdinInterrupted reproduces Ctrl-C while wpgen waits for a
// manifest on standard input.
func TestWorkloadCmdStdinInterrupted(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	blocking := newBlockingReader(t)
	cmd := newRootCmd(testGlobalOptions())
	cmd.SetArgs([]string{"workload", "-"})
	cmd.SetIn(blocking)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	errs := make(chan error, 1)
	go func() { errs <- cmd.ExecuteContext(ctx) }()
	waitStarted(t, blocking.started)
	cancel()

	require.ErrorIs(t, waitResult(t, errs), context.Canceled)
}

// TestCommandsNamedInputInterrupted reproduces Ctrl-C while wpgen waits for
// an input file that is a named pipe, for example /dev/stdin or the result
// of a process substitution.
func TestCommandsNamedInputInterrupted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args func(pipe string) []string
	}{
		{name: "workload", args: func(pipe string) []string { return []string{"workload", pipe} }},
		{name: "check policy", args: func(pipe string) []string { return []string{"check", pipe, "--image", "img:1"} }},
		{
			name: "check workload",
			args: func(pipe string) []string {
				return []string{"check", "-", "--workload", pipe}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pipe := namedPipe(t)
			keepOpen(t, pipe)

			// The policy on standard input is complete, so that the check
			// goes on to the workload pipe.
			policy := newPolicy(t, map[string][]string{"web": {"/usr/bin/web"}})
			stdin := strings.NewReader(policyYAML(t, policy))

			ctx, cancel := context.WithCancel(t.Context())
			cmd := newRootCmd(testGlobalOptions())
			cmd.SetArgs(tt.args(pipe))
			cmd.SetIn(stdin)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			errs := make(chan error, 1)
			go func() { errs <- cmd.ExecuteContext(ctx) }()
			time.Sleep(50 * time.Millisecond)
			cancel()

			require.ErrorIs(t, waitResult(t, errs), context.Canceled)
		})
	}
}
