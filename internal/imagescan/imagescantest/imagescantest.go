// Package imagescantest builds small container images on disk for tests.
package imagescantest

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
)

const (
	dirMode     = 0o755
	symlinkMode = 0o777
)

// Entry is one entry of a layer tar stream.
type Entry struct {
	Name     string
	Typeflag byte
	Mode     int64
	Linkname string
	Content  string
}

// Reg returns a regular file entry. The content of the file is its name.
func Reg(name string, mode int64) Entry {
	return Entry{Name: name, Typeflag: tar.TypeReg, Mode: mode, Content: name}
}

// Dir returns a directory entry.
func Dir(name string) Entry {
	return Entry{Name: name, Typeflag: tar.TypeDir, Mode: dirMode}
}

// Symlink returns a symbolic link entry.
func Symlink(name, target string) Entry {
	return Entry{Name: name, Typeflag: tar.TypeSymlink, Mode: symlinkMode, Linkname: target}
}

// Hardlink returns a hard link entry.
func Hardlink(name, target string, mode int64) Entry {
	return Entry{Name: name, Typeflag: tar.TypeLink, Mode: mode, Linkname: target}
}

// NewLayer returns an uncompressed layer with the given entries, in order.
func NewLayer(t *testing.T, entries ...Entry) v1.Layer {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.Name,
			Typeflag: e.Typeflag,
			Mode:     e.Mode,
			Linkname: e.Linkname,
			Size:     int64(len(e.Content)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if e.Content != "" {
			_, err := tw.Write([]byte(e.Content))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())

	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	return layer
}

// WriteOCIDir stores a linux/amd64 image made of the given layers in a new
// OCI layout directory and returns the path of the directory.
func WriteOCIDir(t *testing.T, layers ...v1.Layer) string {
	t.Helper()

	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)

	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.OS = "linux"
	cfg.Architecture = "amd64"
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)

	path := t.TempDir()
	lp, err := layout.Write(path, empty.Index)
	require.NoError(t, err)
	require.NoError(t, lp.AppendImage(img))
	return path
}

// Load loads an image with imagescan.Load and removes its temporary files
// when the test ends. The cleanup is registered before the error check, so
// it also runs when the load fails.
func Load(t *testing.T, input string, opts imagescan.LoadOptions) *imagescan.Image {
	t.Helper()

	img, err := imagescan.Load(t.Context(), input, opts)
	t.Cleanup(func() {
		if cleanupErr := img.Cleanup(); cleanupErr != nil {
			t.Errorf("cannot clean up image %q: %v", input, cleanupErr)
		}
	})
	require.NoError(t, err)
	return img
}

// LoadOCIDir loads the OCI layout directory at path, as Load does.
func LoadOCIDir(t *testing.T, path string) *imagescan.Image {
	t.Helper()

	return Load(t, path, imagescan.LoadOptions{Sources: []string{"oci-dir"}})
}
