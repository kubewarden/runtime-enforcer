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
