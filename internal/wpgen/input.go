package wpgen

import (
	"context"
	"io"
)

// contextReader is a reader that stops waiting for r when ctx is cancelled.
//
// A read of standard input blocks until the user types or closes the input,
// and Go cannot interrupt it. When ctx is cancelled, Read returns the error
// of ctx at once, and the blocked read stays in its goroutine until the
// process exits.
type contextReader struct {
	ctx context.Context //nolint:containedctx // the reader must watch ctx on every Read.
	r   io.Reader
}

type readResult struct {
	data []byte
	err  error
}

func newContextReader(ctx context.Context, r io.Reader) io.Reader {
	return &contextReader{ctx: ctx, r: r}
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}

	// The goroutine reads into its own buffer: after a cancellation, the
	// caller can reuse p while the read still runs.
	done := make(chan readResult, 1)
	go func() {
		buf := make([]byte, len(p))
		n, err := c.r.Read(buf)
		done <- readResult{data: buf[:n], err: err}
	}()

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case res := <-done:
		return copy(p, res.data), res.err
	}
}
