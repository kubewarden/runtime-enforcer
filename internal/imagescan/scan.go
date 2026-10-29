package imagescan

import (
	"fmt"
	"slices"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
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

// ResolveLinks returns the real path of each of the given paths that goes
// through a symbolic link in the image, either in its last element or in one
// of its directories. Paths that do not exist, or that are already real
// paths, are not in the result.
func ResolveLinks(img *image.Image, paths []string) (map[string]string, error) {
	tree := img.SquashedTree()
	links := map[string]string{}
	for _, p := range paths {
		found, resolution, err := tree.File(file.Path(p), filetree.FollowBasenameLinks)
		if filetree.IsUnresolvableLink(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %q: %w", p, err)
		}
		if !found || !resolution.HasReference() {
			continue
		}
		if realPath := string(resolution.RealPath); realPath != p {
			links[p] = realPath
		}
	}
	return links, nil
}
