// Package imagescantest builds small container images on disk for tests.
package imagescantest

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"io"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
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

// Reg returns a regular file entry. The file is a small ELF program, so that
// it is an executable when its mode has an execute bit.
func Reg(name string, mode int64) Entry {
	return File(name, mode, ELF(ELFSpec{Type: elf.ET_EXEC}))
}

// Library returns a regular file entry that is an ELF shared library.
func Library(name string, mode int64) Entry {
	return File(name, mode, ELF(ELFSpec{Type: elf.ET_DYN, Dynamic: true}))
}

// Script returns a regular file entry that starts with a shebang line.
func Script(name string, mode int64) Entry {
	return File(name, mode, []byte("#!/bin/sh\necho "+name+"\n"))
}

// Data returns a regular file entry that is neither ELF nor a script.
func Data(name string, mode int64) Entry {
	return File(name, mode, []byte("data of "+name+"\n"))
}

// File returns a regular file entry with the given content.
func File(name string, mode int64, content []byte) Entry {
	return Entry{Name: name, Typeflag: tar.TypeReg, Mode: mode, Content: string(content)}
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

// HostPlatform is the platform that the commands select by default:
// linux with the architecture of the host.
func HostPlatform() string {
	return "linux/" + runtime.GOARCH
}

// WriteOCIDir stores an image of the host platform, made of the given
// layers, in a new OCI layout directory and returns the path of the
// directory. The commands select the host platform by default, so they find
// the image without --platform on every host.
func WriteOCIDir(t *testing.T, layers ...v1.Layer) string {
	t.Helper()

	return WriteOCIDirFor(t, HostPlatform(), layers...)
}

// WriteOCIDirFor is WriteOCIDir for an image that declares the given
// platform, for example "linux/arm64".
func WriteOCIDirFor(t *testing.T, platform string, layers ...v1.Layer) string {
	t.Helper()

	path := t.TempDir()
	lp, err := layout.Write(path, empty.Index)
	require.NoError(t, err)
	require.NoError(t, lp.AppendImage(newImage(t, platform, layers...)))
	return path
}

// WriteDockerArchive stores an image that declares the given platform in a
// new archive in the format of "docker save", and returns the path of the
// archive.
func WriteDockerArchive(t *testing.T, platform string, layers ...v1.Layer) string {
	t.Helper()

	tag, err := name.NewTag("registry.example/test:1")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.WriteToFile(path, tag, newImage(t, platform, layers...)))
	return path
}

// newImage returns an image made of the layers, with the platform in its
// configuration.
func newImage(t *testing.T, platform string, layers ...v1.Layer) v1.Image {
	t.Helper()

	p, err := v1.ParsePlatform(platform)
	require.NoError(t, err)

	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)

	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.OS = p.OS
	cfg.Architecture = p.Architecture
	cfg.Variant = p.Variant
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
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
