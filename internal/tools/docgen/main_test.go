package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd(t *testing.T) {
	tests := []struct {
		tool   string
		name   string
		prefix string
	}{
		{tool: toolKubectlPlugin, name: "runtime-enforcer", prefix: "kubectl "},
		{tool: toolWpgen, name: "wpgen", prefix: ""},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			root, prefix, err := rootCmd(tt.tool)
			require.NoError(t, err)
			assert.Equal(t, tt.name, root.Name())
			assert.Equal(t, tt.prefix, prefix)
		})
	}

	_, _, err := rootCmd("nope")
	require.ErrorContains(t, err, `unknown tool "nope"`)
}
