package wpgen

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
)

// update rewrites the golden files with the current output:
//
//	go test ./internal/wpgen -update
//
//nolint:gochecknoglobals // test flags are package variables.
var update = flag.Bool("update", false, "rewrite the golden files in testdata with the current output")

// golangSnapshot is the scan fixture of a real image. See CONTRIBUTING.md to
// regenerate it.
const golangSnapshot = "golang-1.12-alpine-amd64.scan.json"

// assertGolden compares the output with the golden file testdata/<name>.golden.
// With -update, it writes the output to the file instead.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()

	path := filepath.Join("testdata", name+".golden")
	if *update {
		require.NoError(t, os.WriteFile(path, []byte(got), 0o600))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "run 'go test ./internal/wpgen -update' to create the golden file")
	assert.Equal(t, string(want), got, "run 'go test ./internal/wpgen -update' and review the diff")
}

// loadSnapshot reads a scan fixture from testdata.
func loadSnapshot(t *testing.T, name string) *imagescan.Snapshot {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", name))
	require.NoError(t, err)
	defer f.Close()

	snapshot, err := imagescan.ReadSnapshot(f)
	require.NoError(t, err)
	return snapshot
}

// scannedFromSnapshot returns the scanned image that scanImage returns for the
// image of the snapshot, with the same options and lookup paths. Each lookup
// path must be in the lookup paths of the snapshot.
func scannedFromSnapshot(
	t *testing.T,
	snapshot *imagescan.Snapshot,
	opts scanOptions,
	lookup []string,
) *scannedImage {
	t.Helper()

	result, err := snapshot.Result(lookup)
	require.NoError(t, err)
	return newScannedImage(result, &opts)
}
