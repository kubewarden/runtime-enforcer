package wpgen

import (
	"context"
	"io"
	"os"
)

// openInput returns the input named by file: the given stdin when file is
// "-", otherwise the file with that name. The reads of the returned reader
// stop when ctx is cancelled, see contextReader. The caller must close the
// returned reader.
//
// The open of a named pipe blocks until a writer opens the other end, so the
// open also stops when ctx is cancelled. When the open finishes after the
// cancellation, the file is closed in the goroutine of the open.
func openInput(ctx context.Context, file string, stdin io.Reader) (io.ReadCloser, error) {
	if file == stdinFile {
		return io.NopCloser(newContextReader(ctx, stdin)), nil
	}

	f, err := openFile(ctx, file)
	if err != nil {
		return nil, err
	}
	return &namedInput{Reader: newContextReader(ctx, f), file: f}, nil
}

// namedInput is a file with the reads of a contextReader.
type namedInput struct {
	io.Reader

	file *os.File
}

func (n *namedInput) Close() error {
	return n.file.Close()
}

type openResult struct {
	file *os.File
	err  error
}

// openFile opens the file, and stops waiting for the open when ctx is
// cancelled. The file belongs either to the caller or to the goroutine of
// the open, so that a late open does not leak the file.
func openFile(ctx context.Context, name string) (*os.File, error) {
	return openFileWith(ctx, name, os.Open)
}

// openFileWith is openFile with the function that opens the file. The tests
// give an open that blocks until they release it.
func openFileWith(ctx context.Context, name string, open func(string) (*os.File, error)) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The channel is unbuffered, so the send only succeeds when the caller
	// still waits. Otherwise the goroutine takes the ctx.Done branch.
	done := make(chan openResult)
	go func() {
		f, err := open(name)
		res := openResult{file: f, err: err}
		select {
		case done <- res:
		case <-ctx.Done():
			// The caller already left. Close the file, when the open
			// succeeded, because nobody else can. Nobody is left to
			// report a close error to.
			if f != nil {
				_ = f.Close()
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-done:
		return res.file, res.err
	}
}

// contextReader is a reader that stops waiting for r when ctx is cancelled.
//
// A read of standard input, or of a named pipe, blocks until the writer
// writes or closes the input, and Go cannot interrupt it. When ctx is
// cancelled, Read returns the error of ctx at once, and the blocked read
// stays in its goroutine until the process exits.
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
