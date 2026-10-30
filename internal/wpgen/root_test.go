package wpgen

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExecute runs wpgen as the binary does, and checks what the user sees
// on standard error: each error once, and no "Error:" line after a verdict.
func TestExecute(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"main": {"/usr/bin/busybox", "/usr/local/bin/gone"},
	}))
	matching := writePolicies(t, newPolicy(t, map[string][]string{
		"main": {"/usr/bin/busybox"},
	}))

	tests := []struct {
		name    string
		args    []string
		code    int
		message string
		errors  int
	}{
		{
			name:    "check fails with a verdict",
			args:    []string{"check", policy, "--image", img, "--image-src", "oci-dir"},
			code:    1,
			message: "1 allowed path is not an executable in the image",
		},
		{
			name:    "check passes",
			args:    []string{"check", matching, "--image", img, "--image-src", "oci-dir"},
			code:    0,
			message: "No allowed path is stale.",
		},
		{
			name:    "command error",
			args:    []string{"check", policy},
			code:    1,
			message: "at least one of the flags in the group [workload image] is required",
			errors:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr strings.Builder
			args := append([]string{"--color", "never"}, tt.args...)
			code := execute(t.Context(), args, strings.NewReader(""), &stdout, &stderr)

			assert.Equal(t, tt.code, code)
			assert.Equal(t, 1, strings.Count(stderr.String(), tt.message), "the message is printed once")
			assert.Equal(t, tt.errors, strings.Count(stderr.String(), "Error:"))
		})
	}
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
