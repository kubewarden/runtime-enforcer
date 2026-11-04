package imagescan_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
)

func TestTakeSnapshot(t *testing.T) {
	t.Parallel()

	img := ist.LoadOCIDir(t, ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"),
		ist.Reg("usr/bin/busybox", 0o755),
		ist.Symlink("usr/bin/sh", "busybox"),
		ist.Symlink("bin", "usr/bin"),
	)))
	// /bin/sh goes through the linked directory /bin, and is not a node of
	// the file tree. The snapshot must resolve it as wpgen does.
	lookup := []string{"/bin/sh", "/usr/bin/busybox", "/bin/sh", "/usr/bin/missing"}

	snapshot, err := imagescan.TakeSnapshot(t.Context(), img.Image, "example:1", "linux/amd64", lookup)
	require.NoError(t, err)

	want, err := imagescan.Scan(t.Context(), img.Image, lookup)
	require.NoError(t, err)
	assert.Equal(t, want.Executables, snapshot.Executables, "the snapshot is the result of Scan")
	assert.Equal(t, want.Links, snapshot.Links, "the snapshot is the result of Scan")
	assert.Equal(t, map[string]string{"/bin/sh": "/usr/bin/busybox"}, snapshot.Links)
	assert.Equal(t, "example:1", snapshot.Image)
	assert.Equal(t, "linux/amd64", snapshot.Platform)
	assert.Equal(t, []string{"/bin/sh", "/usr/bin/busybox", "/usr/bin/missing"}, snapshot.Lookup,
		"the lookup paths are sorted, without duplicates")
}

// literalSnapshot is a snapshot built by hand, for the tests that do not need
// an image.
func literalSnapshot() *imagescan.Snapshot {
	return &imagescan.Snapshot{
		Image:    "example:1",
		Platform: "linux/amd64",
		Lookup:   []string{"/bin/sh", "/usr/bin/busybox", "/usr/bin/missing"},
		Executables: []imagescan.Executable{
			{Path: "/lib/libz.so.1", Kind: imagescan.KindLibrary},
			{Path: "/usr/bin/busybox", Kind: imagescan.KindProgram},
		},
		Links: map[string]string{"/bin/sh": "/usr/bin/busybox"},
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	snapshot := literalSnapshot()

	var buf bytes.Buffer
	require.NoError(t, snapshot.Write(&buf))
	read, err := imagescan.ReadSnapshot(&buf)
	require.NoError(t, err)
	assert.Equal(t, snapshot, read)
}

func TestSnapshotResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		lookup []string
		links  map[string]string
		err    string
	}{
		{
			name:   "all the lookup paths",
			lookup: []string{"/bin/sh", "/usr/bin/busybox", "/usr/bin/missing"},
			links:  map[string]string{"/bin/sh": "/usr/bin/busybox"},
		},
		{
			name:   "a lookup path that is not a link",
			lookup: []string{"/usr/bin/missing"},
			links:  map[string]string{},
		},
		{
			name:   "no lookup paths",
			lookup: nil,
			links:  map[string]string{},
		},
		{
			name:   "a path that is not a lookup path of the snapshot",
			lookup: []string{"/bin/sh", "/usr/bin/sh"},
			err:    `the snapshot of example:1 has no lookup path "/usr/bin/sh"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			snapshot := literalSnapshot()
			result, err := snapshot.Result(tt.lookup)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, snapshot.Executables, result.Executables, "the executables do not depend on the lookup")
			assert.Equal(t, tt.links, result.Links)
		})
	}
}
