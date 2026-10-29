package imagescan

import (
	"fmt"
	"slices"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

const anyExecBit = 0o111

// Executables returns the sorted absolute paths of all the executable files
// in the squashed file system of the image.
//
// A file is executable when it is a regular file, or a hard link, with at
// least one execute permission bit set. Symbolic links are skipped: the
// kernel resolves them before the enforcer sees the exec event, so the
// enforcer always reports the path of the real file.
func Executables(img *image.Image) ([]string, error) {
	refs := img.SquashedTree().AllFiles(file.TypeRegular, file.TypeHardLink)

	paths := make([]string, 0, len(refs))
	for _, ref := range refs {
		entry, err := img.FileCatalog.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("cannot read metadata of %q: %w", ref.RealPath, err)
		}
		if entry.FileInfo == nil || entry.Mode().Perm()&anyExecBit == 0 {
			continue
		}
		paths = append(paths, string(ref.RealPath))
	}

	slices.Sort(paths)
	return slices.Compact(paths), nil
}
