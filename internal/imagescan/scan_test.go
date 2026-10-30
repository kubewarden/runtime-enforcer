package imagescan_test

import (
	"context"
	"debug/elf"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
)

func TestExecutables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		layers   [][]ist.Entry
		expected []string
	}{
		{
			name: "keeps regular files with any exec bit",
			layers: [][]ist.Entry{{
				ist.Dir("usr/"), ist.Dir("usr/bin/"), ist.Dir("etc/"), ist.Dir("opt/"),
				ist.Reg("usr/bin/app", 0o755),
				ist.Reg("usr/bin/owner-only", 0o700),
				ist.Reg("opt/other-only", 0o601),
				ist.Reg("etc/passwd", 0o644),
			}},
			expected: []string{"/opt/other-only", "/usr/bin/app", "/usr/bin/owner-only"},
		},
		{
			name: "normalizes tar names with a ./ prefix",
			layers: [][]ist.Entry{{
				ist.Dir("./usr/"), ist.Dir("./usr/bin/"),
				ist.Reg("./usr/bin/app", 0o755),
			}},
			expected: []string{"/usr/bin/app"},
		},
		{
			name: "skips symbolic links to files and to directories",
			layers: [][]ist.Entry{{
				ist.Dir("usr/"), ist.Dir("usr/bin/"),
				ist.Reg("usr/bin/busybox", 0o755),
				ist.Symlink("usr/bin/ls", "busybox"),
				ist.Symlink("usr/bin/sh", "/usr/bin/busybox"),
				ist.Symlink("bin", "usr/bin"),
			}},
			expected: []string{"/usr/bin/busybox"},
		},
		{
			name: "keeps both names of a hard link",
			layers: [][]ist.Entry{{
				ist.Dir("usr/"), ist.Dir("usr/bin/"),
				ist.Reg("usr/bin/a", 0o755),
				ist.Hardlink("usr/bin/b", "usr/bin/a", 0o755),
			}},
			expected: []string{"/usr/bin/a", "/usr/bin/b"},
		},
		{
			name: "honors a whiteout in a later layer",
			layers: [][]ist.Entry{
				{
					ist.Dir("usr/"),
					ist.Dir("usr/bin/"),
					ist.Reg("usr/bin/kept", 0o755),
					ist.Reg("usr/bin/removed", 0o755),
				},
				{ist.Dir("usr/"), ist.Dir("usr/bin/"), ist.Reg("usr/bin/.wh.removed", 0o644)},
			},
			expected: []string{"/usr/bin/kept"},
		},
		{
			name: "honors an opaque directory in a later layer",
			layers: [][]ist.Entry{
				{ist.Dir("opt/"), ist.Dir("opt/app/"), ist.Reg("opt/app/old", 0o755)},
				{
					ist.Dir("opt/"),
					ist.Dir("opt/app/"),
					ist.Reg("opt/app/.wh..wh..opq", 0o644),
					ist.Reg("opt/app/new", 0o755),
				},
			},
			expected: []string{"/opt/app/new"},
		},
		{
			name: "uses the mode of the topmost layer",
			layers: [][]ist.Entry{
				{
					ist.Dir("usr/"),
					ist.Dir("usr/bin/"),
					ist.Reg("usr/bin/tool", 0o755),
					ist.Reg("usr/bin/script", 0o644),
				},
				{
					ist.Dir("usr/"),
					ist.Dir("usr/bin/"),
					ist.Reg("usr/bin/tool", 0o644),
					ist.Reg("usr/bin/script", 0o755),
				},
			},
			expected: []string{"/usr/bin/script"},
		},
		{
			name: "returns an empty list when the image has no executables",
			layers: [][]ist.Entry{{
				ist.Dir("etc/"), ist.Reg("etc/hostname", 0o644),
			}},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			layers := make([]v1.Layer, 0, len(tt.layers))
			for _, entries := range tt.layers {
				layers = append(layers, ist.NewLayer(t, entries...))
			}
			img := ist.LoadOCIDir(t, ist.WriteOCIDir(t, layers...))

			got, err := imagescan.Executables(t.Context(), img.Image)
			require.NoError(t, err)

			paths := make([]string, 0, len(got))
			for _, e := range got {
				paths = append(paths, e.Path)
			}
			require.Equal(t, tt.expected, paths)
		})
	}
}

func TestExecutablesStopsWhenCancelled(t *testing.T) {
	t.Parallel()

	img := ist.LoadOCIDir(t, ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"),
		ist.Reg("usr/bin/app", 0o755),
	)))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := imagescan.Executables(ctx, img.Image)
	require.ErrorIs(t, err, context.Canceled)
}

func TestExecutablesKinds(t *testing.T) {
	t.Parallel()

	elfFile := func(name string, spec ist.ELFSpec) []ist.Entry {
		return []ist.Entry{ist.File(name, 0o755, ist.ELF(spec))}
	}

	tests := []struct {
		name    string
		entries []ist.Entry
		path    string
		kind    imagescan.Kind
	}{
		{
			name:    "ET_EXEC program",
			entries: elfFile("bin/app", ist.ELFSpec{Type: elf.ET_EXEC}),
			path:    "/bin/app",
			kind:    imagescan.KindProgram,
		},
		{
			name: "dynamically linked PIE",
			entries: elfFile("bin/app", ist.ELFSpec{
				Type: elf.ET_DYN, Interp: true, Dynamic: true, Flags1: elf.DF_1_PIE,
			}),
			path: "/bin/app",
			kind: imagescan.KindProgram,
		},
		{
			name: "static PIE, with DF_1_PIE and no interpreter",
			entries: elfFile("bin/app", ist.ELFSpec{
				Type: elf.ET_DYN, Dynamic: true, Flags1: elf.DF_1_PIE | elf.DF_1_NOW,
			}),
			path: "/bin/app",
			kind: imagescan.KindProgram,
		},
		{
			// An old linker, or glibc's libc.so.6.
			name:    "ET_DYN with an interpreter and no DF_1_PIE",
			entries: elfFile("bin/app", ist.ELFSpec{Type: elf.ET_DYN, Interp: true}),
			path:    "/bin/app",
			kind:    imagescan.KindProgram,
		},
		{
			name:    "ELF that does not parse",
			entries: []ist.Entry{ist.File("bin/app", 0o755, []byte("\x7fELF not really"))},
			path:    "/bin/app",
			kind:    imagescan.KindProgram,
		},
		{
			name:    "script",
			entries: []ist.Entry{ist.Script("bin/entrypoint.sh", 0o755)},
			path:    "/bin/entrypoint.sh",
			kind:    imagescan.KindScript,
		},
		{
			name:    "shared library",
			entries: []ist.Entry{ist.Library("lib/libz.so.1", 0o755)},
			path:    "/lib/libz.so.1",
			kind:    imagescan.KindLibrary,
		},
		{
			name: "dynamic loader, with flags but no DF_1_PIE",
			entries: elfFile("lib/ld.so", ist.ELFSpec{
				Type: elf.ET_DYN, Dynamic: true, Flags1: elf.DF_1_NOW,
			}),
			path: "/lib/ld.so",
			kind: imagescan.KindLibrary,
		},
		{
			name: "hard link to a shared library",
			entries: []ist.Entry{
				ist.Library("lib/libz.so.1", 0o755),
				ist.Hardlink("lib/libz.so", "lib/libz.so.1", 0o755),
			},
			path: "/lib/libz.so",
			kind: imagescan.KindLibrary,
		},
		{
			// The kernel does not run ET_REL files.
			name:    "ELF object file",
			entries: elfFile("lib/object.o", ist.ELFSpec{Type: elf.ET_REL}),
			path:    "/lib/object.o",
			kind:    imagescan.KindUnknown,
		},
		{
			name:    "data file",
			entries: []ist.Entry{ist.Data("etc/ca.crt", 0o755)},
			path:    "/etc/ca.crt",
			kind:    imagescan.KindUnknown,
		},
		{
			name:    "empty file",
			entries: []ist.Entry{ist.File("etc/empty", 0o755, nil)},
			path:    "/etc/empty",
			kind:    imagescan.KindUnknown,
		},
		{
			name:    "file shorter than the ELF magic",
			entries: []ist.Entry{ist.File("etc/short", 0o755, []byte("#"))},
			path:    "/etc/short",
			kind:    imagescan.KindUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			entries := append([]ist.Entry{ist.Dir("bin/"), ist.Dir("lib/"), ist.Dir("etc/")}, tt.entries...)
			img := ist.LoadOCIDir(t, ist.WriteOCIDir(t, ist.NewLayer(t, entries...)))

			got, err := imagescan.Executables(t.Context(), img.Image)
			require.NoError(t, err)
			assert.Contains(t, got, imagescan.Executable{Path: tt.path, Kind: tt.kind})
		})
	}
}

// linksImage has a program, symbolic links to it, and a dangling link.
func linksImage(t *testing.T) *imagescan.Image {
	t.Helper()

	return ist.LoadOCIDir(t, ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"),
		ist.Reg("usr/bin/busybox", 0o755),
		ist.Symlink("usr/bin/sh", "busybox"),
		ist.Symlink("usr/bin/dangling", "/nowhere"),
		ist.Symlink("bin", "usr/bin"),
	)))
}

func TestResolveLinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		// real is the expected real path. Empty means that the path is not
		// in the result.
		real string
	}{
		{name: "symbolic link to a file", path: "/usr/bin/sh", real: "/usr/bin/busybox"},
		{name: "file in a linked directory", path: "/bin/busybox", real: "/usr/bin/busybox"},
		{name: "link in a linked directory", path: "/bin/sh", real: "/usr/bin/busybox"},
		{name: "already a real path", path: "/usr/bin/busybox"},
		{name: "missing path", path: "/usr/bin/missing"},
		{name: "dangling link", path: "/usr/bin/dangling"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			links, err := imagescan.ResolveLinks(linksImage(t).Image, []string{tt.path})
			require.NoError(t, err)

			if tt.real == "" {
				assert.Empty(t, links)
				return
			}
			assert.Equal(t, map[string]string{tt.path: tt.real}, links)
		})
	}
}
