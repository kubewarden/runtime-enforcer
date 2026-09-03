package bpf

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/kernels"
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
			// this method has no limits in input size
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
	tests := []struct {
		kernelVer string
		len       int
		hasError  bool
	}{
		{
			// this is ok
			kernelVer: "5.9",
			len:       stringMapSize7,
			hasError:  false,
		},
		{
			kernelVer: "5.9",
			len:       stringMapSize7 + 1,
			hasError:  true,
		},
		{
			kernelVer: "5.11",
			len:       MaxStringMapsSize,
			hasError:  false,
		},
		{
			kernelVer: "5.11",
			len:       MaxStringMapsSize + 1,
			hasError:  true,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("kernel_%s_len_%d", tt.kernelVer, tt.len), func(t *testing.T) {
			_, _, err := argStringSelectorValue(
				strings.Repeat("a", tt.len),
				false,
				int(kernels.KernelStringToNumeric(tt.kernelVer)),
			)
			if tt.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
