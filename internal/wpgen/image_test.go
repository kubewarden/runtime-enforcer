package wpgen

import (
	"fmt"
	"os"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
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

	return runWpgenWithStdin(t, strings.NewReader(""), args...)
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

	img := testImage(t)
	stdout, stderr, err := runWpgen(t, "image", img,
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
	assert.Contains(t, stderr, fmt.Sprintf("from source %q (%s)", "oci-dir", ist.HostPlatform()))
	assert.Contains(t, stderr, "│ api ", "the summary has a row for the container")
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

// mixedImage has one executable of each kind.
func mixedImage(t *testing.T) string {
	t.Helper()

	return ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"), ist.Dir("usr/lib/"), ist.Dir("etc/"),
		ist.Reg("usr/bin/app", 0o755),
		ist.Script("usr/bin/entrypoint.sh", 0o755),
		ist.Library("usr/lib/libapp.so.1", 0o755),
		ist.Library("usr/lib/libz.so.1", 0o755),
		ist.Data("etc/ca.crt", 0o755),
	))
}

func TestImageCmdSkipsLibrariesAndUnknownFiles(t *testing.T) {
	t.Parallel()

	img := mixedImage(t)

	tests := []struct {
		name     string
		flags    []string
		expected []string
		skipped  []string
	}{
		{
			name:     "default",
			expected: []string{"/usr/bin/app", "/usr/bin/entrypoint.sh"},
			skipped: []string{
				"Use --include-libraries to keep the skipped shared libraries.\n",
				"Use --include-unknown to keep the skipped files that are neither programs nor scripts.\n",
			},
		},
		{
			name:     "include libraries",
			flags:    []string{"--include-libraries"},
			expected: []string{"/usr/bin/app", "/usr/bin/entrypoint.sh", "/usr/lib/libapp.so.1", "/usr/lib/libz.so.1"},
			skipped:  []string{"Use --include-unknown to keep the skipped files"},
		},
		{
			name:  "include libraries and unknown files",
			flags: []string{"--include-libraries", "--include-unknown"},
			expected: []string{
				"/etc/ca.crt",
				"/usr/bin/app",
				"/usr/bin/entrypoint.sh",
				"/usr/lib/libapp.so.1",
				"/usr/lib/libz.so.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			args := append([]string{"image", img, "--image-src", "oci-dir", "--name", "app"}, tt.flags...)
			stdout, stderr, err := runWpgen(t, args...)
			require.NoError(t, err)

			policies, _, err := policydraft.Decode(strings.NewReader(stdout))
			require.NoError(t, err)
			require.Len(t, policies, 1)
			assert.Equal(t, tt.expected, policies[0].Spec.RulesByContainer["main"].Executables.Allowed)

			for _, msg := range tt.skipped {
				assert.Contains(t, stderr, msg)
			}
			if len(tt.skipped) == 0 {
				assert.NotContains(t, stderr, "Use --include")
			}
		})
	}
}

func TestImageCmdWarnThreshold(t *testing.T) {
	t.Parallel()

	img := testImage(t)

	_, stderr, err := runWpgen(t, "image", img, "--image-src", "oci-dir", "--name", "api", "--warn-threshold", "1")
	require.NoError(t, err)
	assert.Contains(t, stderr, "\n\nWARNING: container main allows 2 executables.", "the warning is a paragraph")
	assert.Contains(t, stderr, "protect mode.\n\nAdd this label", "the label hint is a paragraph")

	_, stderr, err = runWpgen(t, "image", img, "--image-src", "oci-dir", "--name", "api", "--warn-threshold", "0")
	require.NoError(t, err)
	assert.NotContains(t, stderr, "WARNING")
}

// TestImageCmdPlaceholderName checks an image that gives no policy name: an
// OCI directory stores no tags. The policy gets a placeholder name, and a
// warning tells the user to replace it.
func TestImageCmdPlaceholderName(t *testing.T) {
	t.Parallel()

	img := testImage(t)
	stdout, stderr, err := runWpgen(t, "image", img, "--image-src", "oci-dir")
	require.NoError(t, err)
	assert.Contains(t, stdout, "  name: todo\n")
	assert.Contains(t, stderr, fmt.Sprintf(
		"WARNING: cannot derive the policy name from %q: the image has no tags.\n"+
			`The policy name is "todo". Use --name, or edit metadata.name.`, img))
	assert.Contains(t, stderr, v1alpha1.PolicyLabelKey+": todo")
}

// TestImageCmdNameFromArchiveTag checks that the policy name of an image from
// a file comes from the tag stored in the image, and not from the file name.
func TestImageCmdNameFromArchiveTag(t *testing.T) {
	t.Parallel()

	archive := ist.WriteDockerArchive(t, ist.HostPlatform(),
		ist.NewLayer(t, ist.Dir("usr/"), ist.Dir("usr/bin/"), ist.Reg("usr/bin/api", 0o755)))
	stdout, stderr, err := runWpgen(t, "image", archive, "--image-src", "file")
	require.NoError(t, err)
	assert.Contains(t, stdout, "  name: test\n", "the archive has the tag registry.example/test:1")
	assert.NotContains(t, stderr, "WARNING")
}

// TestImageCmdPlatform checks --platform with images of a fixed platform,
// whatever the host is.
func TestImageCmdPlatform(t *testing.T) {
	t.Parallel()

	layer := func(t *testing.T) v1.Layer {
		t.Helper()
		return ist.NewLayer(t, ist.Dir("usr/"), ist.Dir("usr/bin/"), ist.Reg("usr/bin/api", 0o755))
	}

	tests := []struct {
		name   string
		source string
		image  func(t *testing.T) string
		err    string
	}{
		{
			name:   "OCI directory of the requested platform",
			source: "oci-dir",
			image:  func(t *testing.T) string { return ist.WriteOCIDirFor(t, "linux/arm64", layer(t)) },
		},
		{
			name:   "OCI directory of another platform",
			source: "oci-dir",
			image:  func(t *testing.T) string { return ist.WriteOCIDirFor(t, "linux/amd64", layer(t)) },
			err:    "mismatched platform (expected linux/arm64)",
		},
		{
			name:   "Docker archive of the requested platform",
			source: "docker-archive",
			image:  func(t *testing.T) string { return ist.WriteDockerArchive(t, "linux/arm64", layer(t)) },
		},
		{
			// The Docker archive source of stereoscope does not check the
			// platform: wpgen checks it.
			name:   "Docker archive of another platform",
			source: "docker-archive",
			image:  func(t *testing.T) string { return ist.WriteDockerArchive(t, "linux/amd64", layer(t)) },
			err:    `mismatched platform (expected linux/arm64): image platform="linux/amd64"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stdout, _, err := runWpgen(t, "image", tt.image(t),
				"--image-src", tt.source, "--name", "api", "--platform", "linux/arm64")
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				assert.Empty(t, stdout, "no policy for an image of another platform")
				return
			}
			require.NoError(t, err)
			assert.Contains(t, stdout, "/usr/bin/api")
		})
	}
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

	tests := []struct {
		name         string
		input        string
		fromFile     bool
		repositories []string
		expected     string
		err          error
		errText      string
	}{
		{name: "short reference", input: "nginx", expected: "nginx"},
		{name: "full reference", input: "docker.io/library/nginx:1.27", expected: "nginx"},
		{name: "digest", input: "ghcr.io/example/team/my_api@sha256:" + sha256Zero, expected: "my-api"},
		{name: "registry with a port", input: "localhost:5000/api:dev", expected: "api"},
		{
			// A daemon returns its tags, but the user typed the reference.
			name:         "reference before the tags",
			input:        "nginx:1.27",
			repositories: []string{"internal/web"},
			expected:     "nginx",
		},
		{
			name:         "tags when the input is not a reference",
			input:        "Not A Reference",
			repositories: []string{"library/alpine"},
			expected:     "alpine",
		},
		{name: "no reference and no tags", input: "Not A Reference", err: errNoPolicyName},
		{
			name:         "file with tags",
			input:        "./images/nginx.tar",
			fromFile:     true,
			repositories: []string{"library/alpine_linux"},
			expected:     "alpine-linux",
		},
		{
			// nginx.tar is a valid reference, but it is the name of a file.
			name:     "file without tags",
			input:    "nginx.tar",
			fromFile: true,
			err:      errNoPolicyName,
		},
		{
			// A label value has at most 63 characters.
			name:    "derived name that is not valid",
			input:   "registry.example/" + strings.Repeat("a", 64),
			errText: "use --name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := policyNameFromImage(tt.input, tt.fromFile, tt.repositories)
			switch {
			case tt.err != nil:
				require.ErrorIs(t, err, tt.err)
			case tt.errText != "":
				require.ErrorContains(t, err, tt.errText)
				require.NotErrorIs(t, err, errNoPolicyName, "a name that is not valid is an error, not a placeholder")
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

// TestPolicyNameFromImageIgnoresLocalFiles checks that a file or a directory
// with the name of the image does not change the policy name. It changes the
// working directory, so it does not run in parallel.
func TestPolicyNameFromImageIgnoresLocalFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.Mkdir("nginx", 0o700))

	got, err := policyNameFromImage("nginx", false, nil)
	require.NoError(t, err)
	assert.Equal(t, "nginx", got)
}

const sha256Zero = "0000000000000000000000000000000000000000000000000000000000000000"
