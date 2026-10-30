package imagescan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
)

// TestMain removes the root temporary directory of stereoscope after all the
// tests end. Failed loads can leave files there, and the tests run in
// parallel, so the cleanup cannot happen inside a single test.
func TestMain(m *testing.M) {
	code := m.Run()
	imagescan.CleanupAll()
	os.Exit(code)
}

func TestValidateSources(t *testing.T) {
	t.Parallel()

	require.NoError(t, imagescan.ValidateSources(imagescan.DefaultSources))
	require.NoError(t, imagescan.ValidateSources([]string{"oci-registry", "containerd"}))

	err := imagescan.ValidateSources([]string{"docker", "nope"})
	require.ErrorContains(t, err, `unknown image source "nope"`)

	require.Error(t, imagescan.ValidateSources(nil))

	// wpgen is built without the containers-storage provider.
	assert.NotContains(t, imagescan.KnownSources(), "containers-storage")
	assert.Contains(t, imagescan.KnownSources(), "pull", "the other providers keep their tags")
	require.ErrorContains(t, imagescan.ValidateSources([]string{"containers-storage"}),
		`unknown image source "containers-storage"`)
}

func TestLoadFallsBackToTheNextSource(t *testing.T) {
	t.Parallel()

	path := ist.WriteOCIDir(t, ist.NewLayer(t, ist.Dir("bin/"), ist.Reg("bin/app", 0o755)))

	img := ist.Load(t, path, imagescan.LoadOptions{
		Sources: []string{"docker-archive", "oci-dir"},
	})

	assert.Equal(t, "oci-dir", img.Source)
}

func TestLoadWithTag(t *testing.T) {
	t.Parallel()

	path := ist.WriteOCIDir(t, ist.NewLayer(t, ist.Dir("bin/"), ist.Reg("bin/app", 0o755)))

	img := ist.Load(t, path, imagescan.LoadOptions{Sources: []string{"file"}})

	assert.Equal(t, "file", img.Source)
}

func TestLoadReportsEverySourceError(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing")

	img, err := imagescan.Load(t.Context(), missing, imagescan.LoadOptions{
		Sources: []string{"docker-archive", "oci-dir"},
	})
	t.Cleanup(func() { _ = img.Cleanup() })
	require.ErrorContains(t, err, "docker-archive: ")
	require.ErrorContains(t, err, "oci-dir: ")
}

func TestLoadRejectsUnknownSources(t *testing.T) {
	t.Parallel()

	img, err := imagescan.Load(t.Context(), "alpine", imagescan.LoadOptions{Sources: []string{"nope"}})
	t.Cleanup(func() { _ = img.Cleanup() })
	require.ErrorContains(t, err, `unknown image source "nope"`)
}

// TestLoadChecksThePlatform uses Docker archives: the Docker archive source
// of stereoscope does not check the platform, so Load must check it.
func TestLoadChecksThePlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		declared  string
		requested string
		err       string
	}{
		{name: "same platform", declared: "linux/arm64", requested: "linux/arm64"},
		{name: "no requested platform", declared: "linux/s390x"},
		{name: "alias of the architecture", declared: "linux/amd64", requested: "linux/x86_64"},
		{
			name:      "variant not requested",
			declared:  "linux/riscv64/rva23",
			requested: "linux/riscv64",
		},
		{name: "same variant", declared: "linux/arm/v6", requested: "linux/arm/v6"},
		{
			name:      "other variant",
			declared:  "linux/arm/v6",
			requested: "linux/arm/v7",
			err:       `mismatched platform (expected linux/arm/v7): image platform="linux/arm/v6"`,
		},
		{
			name:      "other architecture",
			declared:  "linux/amd64",
			requested: "linux/arm64",
			err:       `docker-archive: mismatched platform (expected linux/arm64): image platform="linux/amd64"`,
		},
		{
			name:      "other operating system",
			declared:  "windows/amd64",
			requested: "linux/amd64",
			err:       `mismatched platform (expected linux/amd64): image platform="windows/amd64"`,
		},
		{name: "invalid requested platform", declared: "linux/amd64", requested: "linux/!", err: "invalid platform"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := ist.WriteDockerArchive(t, tt.declared, ist.NewLayer(t, ist.Dir("bin/"), ist.Reg("bin/app", 0o755)))
			opts := imagescan.LoadOptions{Sources: []string{"docker-archive"}, Platform: tt.requested}
			if tt.err == "" {
				img := ist.Load(t, path, opts)
				assert.Equal(t, "docker-archive", img.Source)
				return
			}

			img, err := imagescan.Load(t.Context(), path, opts)
			t.Cleanup(func() { _ = img.Cleanup() })
			require.ErrorContains(t, err, tt.err)
			assert.Nil(t, img)
		})
	}
}

// TestLoadTriesTheNextSourceAfterAPlatformMismatch checks that a mismatch is
// a failure of one source, like the other errors of a source.
func TestLoadTriesTheNextSourceAfterAPlatformMismatch(t *testing.T) {
	t.Parallel()

	path := ist.WriteDockerArchive(t, "linux/amd64", ist.NewLayer(t, ist.Dir("bin/"), ist.Reg("bin/app", 0o755)))
	img, err := imagescan.Load(t.Context(), path, imagescan.LoadOptions{
		Sources:  []string{"docker-archive", "oci-dir"},
		Platform: "linux/arm64",
	})
	t.Cleanup(func() { _ = img.Cleanup() })
	require.ErrorContains(t, err, "docker-archive: mismatched platform")
	require.ErrorContains(t, err, "oci-dir: ", "Load tries the next source after the mismatch")
}

func TestIsFileSource(t *testing.T) {
	t.Parallel()

	for _, source := range []string{"file", "dir", "oci-dir", "oci-archive", "docker-archive"} {
		assert.True(t, imagescan.IsFileSource(source), source)
	}
	for _, source := range []string{"docker", "podman", "registry", "pull", "daemon", "nope"} {
		assert.False(t, imagescan.IsFileSource(source), source)
	}
}
