package wpgen

import (
	"bytes"
	"os"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
)

// TestMain removes the root temporary directory of stereoscope after all the
// tests end, as main does for the real binary.
func TestMain(m *testing.M) {
	code := m.Run()
	imagescan.CleanupAll()
	os.Exit(code)
}

func runWpgen(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.ExecuteContext(t.Context())
	return stdout.String(), stderr.String(), err
}

func testImage(t *testing.T) string {
	t.Helper()

	return ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"), ist.Dir("etc/"),
		ist.Reg("usr/bin/api", 0o755),
		ist.Reg("usr/bin/migrate", 0o755),
		ist.Symlink("usr/bin/run", "api"),
		ist.Reg("etc/api.conf", 0o644),
	))
}

func TestImageCmd(t *testing.T) {
	t.Parallel()

	stdout, stderr, err := runWpgen(t, "image", testImage(t),
		"--image-src", "oci-dir",
		"--container-name", "api",
		"--name", "api",
		"--namespace", "prod",
	)
	require.NoError(t, err)

	assert.Equal(t, `apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
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
`, stdout)
	assert.Contains(t, stderr, `from source "oci-dir" (linux/amd64)`)
	assert.Contains(t, stderr, `container "api" (image `)
	assert.Contains(t, stderr, "): 2 executables\n")
	assert.Contains(t, stderr, "runtimeenforcer.kubewarden.io/policy: api\n")
	assert.NotContains(t, stderr, "WARNING")
	assert.NotContains(t, stderr, "--container-name")
}

func TestImageCmdDefaults(t *testing.T) {
	t.Parallel()

	stdout, stderr, err := runWpgen(t, "image", testImage(t), "--image-src", "oci-dir", "--name", "api", "-o", "json")
	require.NoError(t, err)

	assert.Contains(t, stdout, `"namespace": "default"`)
	assert.Contains(t, stdout, `"mode": "monitor"`)
	assert.Contains(t, stdout, `"main": {`)
	assert.Contains(t, stderr, `Make sure that the container is named "main" in the pod`)
}

func TestImageCmdWarnThreshold(t *testing.T) {
	t.Parallel()

	img := testImage(t)

	_, stderr, err := runWpgen(t, "image", img, "--image-src", "oci-dir", "--name", "api", "--warn-threshold", "1")
	require.NoError(t, err)
	assert.Contains(t, stderr, `WARNING: container "main" allows 2 executables.`)

	_, stderr, err = runWpgen(t, "image", img, "--image-src", "oci-dir", "--name", "api", "--warn-threshold", "0")
	require.NoError(t, err)
	assert.NotContains(t, stderr, "WARNING")
}

func TestImageCmdRequiresNameForLocalImagesWithoutTags(t *testing.T) {
	t.Parallel()

	stdout, _, err := runWpgen(t, "image", testImage(t), "--image-src", "oci-dir")
	require.ErrorContains(t, err, "use --name")
	assert.Empty(t, stdout)
}

func TestImageCmdValidatesFlagsBeforeLoading(t *testing.T) {
	t.Parallel()

	_, stderr, err := runWpgen(t, "image", "does-not-matter",
		"--mode", "enforce",
		"--output", "toml",
		"--container-name", "Not_Valid",
		"--namespace", "Bad_NS",
		"--name", "bad_name",
		"--warn-threshold", "-1",
		"--image-src", "nope",
	)
	require.Error(t, err)
	for _, msg := range []string{
		`invalid mode "enforce"`,
		`invalid output format "toml"`,
		`invalid container name "Not_Valid"`,
		`invalid namespace "Bad_NS"`,
		`invalid policy name "bad_name"`,
		"invalid warn threshold -1",
		`unknown image source "nope"`,
	} {
		require.ErrorContains(t, err, msg)
	}
	assert.NotContains(t, stderr, "Loading image")
}

func TestPolicyNameFromImage(t *testing.T) {
	t.Parallel()

	emptyImage := &imagescan.Image{Image: &image.Image{}}

	tests := []struct {
		input    string
		expected string
		err      string
	}{
		{input: "nginx", expected: "nginx"},
		{input: "docker.io/library/nginx:1.27", expected: "nginx"},
		{input: "ghcr.io/example/team/my_api@sha256:" + sha256Zero, expected: "my-api"},
		{input: "localhost:5000/api:dev", expected: "api"},
		{input: "Not A Reference", err: "use --name"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			got, err := policyNameFromImage(tt.input, emptyImage)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

const sha256Zero = "0000000000000000000000000000000000000000000000000000000000000000"
