package wpgen

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	wpt "github.com/kubewarden/runtime-enforcer/internal/workloadparse/workloadparsetest"
)

func TestPainterRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     string
		env      map[string]string
		terminal bool
		enabled  bool
	}{
		{name: "auto on a terminal", mode: colorAuto, terminal: true, enabled: true},
		{name: "auto on a pipe", mode: colorAuto, terminal: false, enabled: false},
		{name: "NO_COLOR on a terminal", mode: colorAuto, env: map[string]string{"NO_COLOR": "1"}, terminal: true},
		{
			name:     "empty NO_COLOR is ignored",
			mode:     colorAuto,
			env:      map[string]string{"NO_COLOR": ""},
			terminal: true,
			enabled:  true,
		},
		{
			name:    "CLICOLOR_FORCE on a pipe",
			mode:    colorAuto,
			env:     map[string]string{"CLICOLOR_FORCE": "1"},
			enabled: true,
		},
		{name: "CLICOLOR_FORCE=0 is ignored", mode: colorAuto, env: map[string]string{"CLICOLOR_FORCE": "0"}},
		{
			name: "NO_COLOR wins over CLICOLOR_FORCE",
			mode: colorAuto,
			env:  map[string]string{"NO_COLOR": "1", "CLICOLOR_FORCE": "1"},
		},
		{name: "always on a pipe", mode: colorAlways, enabled: true},
		{name: "always wins over NO_COLOR", mode: colorAlways, env: map[string]string{"NO_COLOR": "1"}, enabled: true},
		{name: "never on a terminal", mode: colorNever, terminal: true},
		{name: "never wins over CLICOLOR_FORCE", mode: colorNever, env: map[string]string{"CLICOLOR_FORCE": "1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g := &globalOptions{
				Color:      tt.mode,
				getenv:     func(k string) string { return tt.env[k] },
				isTerminal: func(io.Writer) bool { return tt.terminal },
			}
			assert.Equal(t, tt.enabled, g.painter(&bytes.Buffer{}).enabled)
		})
	}
}

func TestPainterStyles(t *testing.T) {
	t.Parallel()

	off := painter{}
	assert.Equal(t, "text", off.failure("text"))

	on := painter{enabled: true}
	assert.Equal(t, ansiBold+ansiRed+"text"+ansiReset, on.failure("text"))
	assert.Equal(t, ansiBold+ansiGreen+"text"+ansiReset, on.success("text"))
	assert.Equal(t, ansiBold+ansiYellow+"text"+ansiReset, on.warning("text"))
	assert.Equal(t, ansiYellow+"text"+ansiReset, on.notice("text"))
	assert.Equal(t, ansiBold+"text"+ansiReset, on.strong("text"))
}

func TestColorFlag(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	policy := writePolicies(t, newPolicy(t, map[string][]string{"shell": {"/usr/bin/busybox", "/usr/local/bin/gone"}}))
	workload := wpt.WriteFile(t, deploymentWith(
		corev1.Container{Name: "shell", Image: img},
		corev1.Container{Name: "unknown", Image: img},
	))
	args := []string{"check", policy, "--workload", workload, "--image-src", "oci-dir"}

	stdout, stderr, err := runWpgen(t, append(args, "--color", "always")...)
	require.Error(t, err)
	assert.Contains(t, stdout, ansiBold+"shell"+ansiReset, "the container name is bold")
	assert.Contains(t, stderr, ansiBold+ansiRed+"1 allowed path is not an executable in the images:"+ansiReset)
	assert.Contains(t, stderr, ansiYellow+`The policy has no rules for container "unknown"`)
	assert.NotContains(t, stdout, ansiRed, "the tables have no colors")

	for _, mode := range []string{colorNever, colorAuto} {
		stdout, stderr, err = runWpgen(t, append(args, "--color", mode)...)
		require.Error(t, err)
		assert.NotContainsf(t, stdout+stderr, "\x1b[", "no escape codes with --color=%s on a buffer", mode)
	}

	_, _, err = runWpgen(t, append(args, "--color", "sometimes")...)
	require.EqualError(t, err, `invalid color mode "sometimes": must be "auto", "always" or "never"`)
}

func TestStreamsSeparate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		terminals map[io.Writer]bool
		expected  string
	}{
		{name: "both streams on the terminal", terminals: map[io.Writer]bool{}, expected: "\n"},
		{name: "standard output redirected", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out, errOut bytes.Buffer
			g := &globalOptions{
				Color:      colorNever,
				getenv:     func(string) string { return "" },
				isTerminal: func(io.Writer) bool { return tt.terminals != nil },
			}
			g.streams(&out, &errOut).separate()
			assert.Equal(t, tt.expected, errOut.String())
			assert.Empty(t, out.String(), "standard output never gets the blank line")
		})
	}
}

func TestReportedError(t *testing.T) {
	t.Parallel()

	reported := &reportedError{msg: "2 allowed paths are not executables in the images"}
	assert.True(t, isReported(reported))
	assert.True(t, isReported(fmt.Errorf("wrapped: %w", reported)))
	assert.False(t, isReported(errors.New("other")))
}
