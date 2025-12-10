//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringPaddedLen(t *testing.T) {
	tests := []struct {
		name     string
		in       int
		expected int
	}{
		{
			in:       1,
			expected: stringMapSize0,
		},
		{
			in:       stringMapsKeyIncSize,
			expected: stringMapSize0,
		},
		{
			in:       stringMapsKeyIncSize + 1,
			expected: stringMapSize1,
		},
		{
			in:       stringMapsKeyIncSize*5 + 1,
			expected: stringMapSize5,
		},
		{
			in:       stringMapsKeyIncSize*6 + 1,
			expected: stringMapSize6,
		},
		{
			in:       stringMapSize6 + 1,
			expected: stringMapSize7,
		},
		{
			in:       stringMapSize9 + 1,
			expected: stringMapSize10,
		},
		{
			// this method has no limits
			in:       stringMapSize10 * 10,
			expected: stringMapSize10,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("input_%d", tt.in), func(t *testing.T) {
			require.Equal(t, tt.expected, stringPaddedLen(tt.in))
		})
	}
}

func TestArgStringSelectorValue(t *testing.T) {
	getExpectedValue := func(v string) [MaxStringMapsSize]byte {
		ret := [MaxStringMapsSize]byte{}
		copy(ret[:], []byte(v))
		return ret
	}

	tests := []struct {
		name string
		in   string
	}{
		{
			// example input taken from a kind cluster with cri-containerd
			name: "less than 256 bytes",
			in:   "/usr/bin/cri-containerd",
		},
		{
			// example input taken from a kind cluster with cri-containerd
			name: "more than 256 bytes",
			in:   strings.Repeat("AB", 500),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outBytes, _, err := argStringSelectorValue(tt.in, false)
			require.NoError(t, err)
			require.Equal(t, getExpectedValue(tt.in), outBytes)
		})
	}
}
