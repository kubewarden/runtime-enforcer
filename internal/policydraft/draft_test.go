package policydraft_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
)

func TestNewRejectsInvalidMode(t *testing.T) {
	t.Parallel()

	_, err := policydraft.New("p", "default", "enforce", nil)
	require.ErrorContains(t, err, `invalid mode "enforce"`)
}

func TestEncode(t *testing.T) {
	t.Parallel()

	policy, err := policydraft.New("api", "prod", "monitor", map[string][]string{
		"api": {"/usr/bin/api", "/usr/bin/migrate"},
	})
	require.NoError(t, err)

	tests := []struct {
		format   string
		expected string
	}{
		{
			format: policydraft.FormatYAML,
			expected: `apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: api
  namespace: prod
spec:
  mode: monitor
  rulesByContainer:
    api:
      executables:
        allowed:
        - /usr/bin/api
        - /usr/bin/migrate
`,
		},
		{
			format: policydraft.FormatJSON,
			expected: `{
  "apiVersion": "runtimeenforcer.kubewarden.io/v1alpha1",
  "kind": "WorkloadPolicy",
  "metadata": {
    "name": "api",
    "namespace": "prod"
  },
  "spec": {
    "mode": "monitor",
    "rulesByContainer": {
      "api": {
        "executables": {
          "allowed": [
            "/usr/bin/api",
            "/usr/bin/migrate"
          ]
        }
      }
    }
  }
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			require.NoError(t, policydraft.Encode(&buf, policy, tt.format))
			assert.Equal(t, tt.expected, buf.String())
		})
	}
}

func TestEncodeRejectsInvalidFormat(t *testing.T) {
	t.Parallel()

	policy, err := policydraft.New("p", "default", "monitor", nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.ErrorContains(t, policydraft.Encode(&buf, policy, "toml"), `invalid output format "toml"`)
}

func TestEncodeAll(t *testing.T) {
	t.Parallel()

	first, err := policydraft.New("first", "", "monitor", map[string][]string{"a": {"/a"}})
	require.NoError(t, err)
	second, err := policydraft.New("second", "", "protect", map[string][]string{"b": {"/b"}})
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, policydraft.EncodeAll(&buf, []*v1alpha1.WorkloadPolicy{first, second}, policydraft.FormatYAML))
	assert.Equal(t, `apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: first
spec:
  mode: monitor
  rulesByContainer:
    a:
      executables:
        allowed:
        - /a
---
apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: second
spec:
  mode: protect
  rulesByContainer:
    b:
      executables:
        allowed:
        - /b
`, buf.String())

	buf.Reset()
	require.NoError(t, policydraft.EncodeAll(&buf, []*v1alpha1.WorkloadPolicy{first, second}, policydraft.FormatJSON))
	assert.Equal(t, 2, strings.Count(buf.String(), `"kind": "WorkloadPolicy"`))
	assert.NotContains(t, buf.String(), "---")
}
