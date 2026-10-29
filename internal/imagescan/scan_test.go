package imagescan_test

import (
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

			got, err := imagescan.Executables(img.Image)
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestResolveLinks(t *testing.T) {
	t.Parallel()

	img := ist.LoadOCIDir(t, ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"),
		ist.Reg("usr/bin/busybox", 0o755),
		ist.Symlink("usr/bin/sh", "busybox"),
		ist.Symlink("usr/bin/dangling", "/nowhere"),
		ist.Symlink("bin", "usr/bin"),
	)))

	links, err := imagescan.ResolveLinks(img.Image, []string{
		"/usr/bin/sh",
		"/bin/busybox",
		"/bin/sh",
		"/usr/bin/busybox",
		"/usr/bin/missing",
		"/usr/bin/dangling",
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"/usr/bin/sh":  "/usr/bin/busybox",
		"/bin/busybox": "/usr/bin/busybox",
		"/bin/sh":      "/usr/bin/busybox",
	}, links)
}
