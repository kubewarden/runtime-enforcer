package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const (
	SpanChannelBufferSize = 100
	ScannerBuffer         = 1024 * 1024 // 1mb
)

// OtelLogStream maintains a io.ReadCloser derived from kubernetes pod/logs API
// and keeps reading ptrace.Traces and ptrace.Span from it.
type OtelLogStream struct {
	stream io.ReadCloser
	spans  chan *ptrace.Span
	cancel context.CancelFunc
}

func NewOtelLogStream(
	stream io.ReadCloser,
) (*OtelLogStream, error) {
	return &OtelLogStream{
		stream: stream,
		spans:  make(chan *ptrace.Span, SpanChannelBufferSize),
	}, nil
}

func (s *OtelLogStream) Stop() {
	s.cancel()
	s.stream.Close()
}

func (s *OtelLogStream) extractSpans(trace *ptrace.Traces) {
	for _, resourceSpan := range trace.ResourceSpans().All() {
		for _, scopeSpan := range resourceSpan.ScopeSpans().All() {
			for _, span := range scopeSpan.Spans().All() {
				s.spans <- &span
			}
		}
	}
}

func (s *OtelLogStream) Start(ctx context.Context, t *testing.T) error {
	var err error

	var buffer bytes.Buffer
	var ready bool

	ctx, cancel := context.WithCancel(ctx)

	s.cancel = cancel

	for {
		scanner := bufio.NewScanner(s.stream)
		scanner.Buffer([]byte{}, ScannerBuffer)
		for {
			if !scanner.Scan() {
				time.Sleep(time.Second)
				break
			}

			select {
			case <-ctx.Done():
				return errors.New("the operation times out")
			default:
			}

			if !ready {
				if strings.Contains(scanner.Text(), "Everything is ready") {
					ready = true
				}
				continue
			}

			_, err = buffer.Write(scanner.Bytes())
			require.NoError(t, err)

			var traceEvent ptrace.Traces
			var unmarshaler ptrace.JSONUnmarshaler

			traceEvent, err = unmarshaler.UnmarshalTraces(buffer.Bytes())
			if err != nil {
				continue
			}

			buffer.Reset()
			s.extractSpans(&traceEvent)
		}
	}
}

// WaitUntil keeps calling a specified callback function for each span it receives from open telemetry
// until its context times out or the callback function returns true.
func (s *OtelLogStream) WaitUntil(
	ctx context.Context,
	timeout time.Duration,
	cb func(span *ptrace.Span) (bool, error),
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var ok bool
	var err error

	for {
		select {
		case <-ctx.Done():
			return errors.New("the operation timed out")
		case span := <-s.spans:
			ok, err = cb(span)
			if err != nil {
				return fmt.Errorf("the operation failed: %w", err)
			}
			if ok {
				return nil
			}
		}
	}
}
