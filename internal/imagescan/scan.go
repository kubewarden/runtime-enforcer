package imagescan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
)

const anyExecBit = 0o111

// Executable is a file with an execute permission bit, and its kind.
type Executable struct {
	Path string `json:"path"`
	Kind Kind   `json:"kind"`
}

// Executables returns all the executable files in the squashed file system
// of the image, sorted by path, with their kind.
//
// A file is executable when it is a regular file, or a hard link, with at
// least one execute permission bit set. Symbolic links are skipped: the
// kernel resolves them before the enforcer sees the exec event, so the
// enforcer always reports the path of the real file.
func Executables(img *image.Image) ([]Executable, error) {
	refs := img.SquashedTree().AllFiles(file.TypeRegular, file.TypeHardLink)

	executables := make([]Executable, 0, len(refs))
	for _, ref := range refs {
		entry, err := img.FileCatalog.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("cannot read metadata of %q: %w", ref.RealPath, err)
		}
		if entry.FileInfo == nil || entry.Mode().Perm()&anyExecBit == 0 {
			continue
		}

		kind, err := classifyPath(img, ref.RealPath)
		if err != nil {
			return nil, err
		}
		executables = append(executables, Executable{Path: string(ref.RealPath), Kind: kind})
	}

	slices.SortFunc(executables, func(a, b Executable) int { return strings.Compare(a.Path, b.Path) })
	return slices.CompactFunc(executables, func(a, b Executable) bool { return a.Path == b.Path }), nil
}

func classifyPath(img *image.Image, p file.Path) (Kind, error) {
	rc, err := img.OpenPathFromSquash(p)
	if err != nil {
		return "", fmt.Errorf("cannot read %q: %w", p, err)
	}
	defer rc.Close()

	kind, err := classify(rc)
	if err != nil {
		return "", fmt.Errorf("cannot read %q: %w", p, err)
	}
	return kind, nil
}

// Result is the result of the scan of an image.
type Result struct {
	// Executables are all the executables of the image, sorted by path.
	Executables []Executable
	// Links maps each looked up path that goes through a symbolic link to its
	// real path.
	Links map[string]string
}

// Scan lists the executables of the image, and resolves the lookup paths
// through the symbolic links of the image. A lookup path that is already a
// real path, such as the path of an executable, is not in Links.
func Scan(img *image.Image, lookup []string) (*Result, error) {
	executables, err := Executables(img)
	if err != nil {
		return nil, err
	}
	links, err := ResolveLinks(img, lookup)
	if err != nil {
		return nil, err
	}
	return &Result{Executables: executables, Links: links}, nil
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
