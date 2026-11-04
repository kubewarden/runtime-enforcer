package imagescan

import (
	"context"
	"fmt"
	"path"
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
// enforcer always reports the path of the real file. A hard link has the
// kind of the file that it named when a layer created it, as at runtime.
//
// Executables reads the start of each executable file. It stops with the
// error of ctx when ctx is cancelled.
func Executables(ctx context.Context, img *image.Image) ([]Executable, error) {
	refs := img.SquashedTree().AllFiles(file.TypeRegular, file.TypeHardLink)

	executables := make([]Executable, 0, len(refs))
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, err := img.FileCatalog.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("cannot read metadata of %q: %w", ref.RealPath, err)
		}
		if entry.FileInfo == nil || entry.Mode().Perm()&anyExecBit == 0 {
			continue
		}

		kind, err := classifyFile(img, ref, entry)
		if err != nil {
			return nil, err
		}
		executables = append(executables, Executable{Path: string(ref.RealPath), Kind: kind})
	}

	slices.SortFunc(executables, func(a, b Executable) int { return strings.Compare(a.Path, b.Path) })
	return slices.CompactFunc(executables, func(a, b Executable) bool { return a.Path == b.Path }), nil
}

// classifyFile returns the kind of the file. It reads the contents that the
// file has at runtime, and not the contents of its path in the squashed tree,
// which can be wrong for a hard link.
//
// A hard link is a second name for a file. Stereoscope binds a hard link to its
// target only when both are in the same layer. When the target is in a lower
// layer, the entry keeps the type TypeHardLink and the name of the target. At
// runtime, the link has the contents of the target at the time the link was
// created, so a later layer can replace or delete the target without an effect
// on the link. classifyFile reads the target in the squashed tree of the layer
// that added the link. When it cannot find a regular file there, it returns
// KindProgram, because dropping a program from a policy blocks the workload.
func classifyFile(img *image.Image, ref file.Reference, entry filetree.IndexEntry) (Kind, error) {
	targetRef, ok := hardLinkTarget(img, ref, entry)
	if !ok {
		return KindProgram, nil
	}

	rc, err := img.OpenReference(targetRef)
	if err != nil {
		return "", fmt.Errorf("cannot read %q: %w", ref.RealPath, err)
	}
	defer rc.Close()

	kind, err := classify(rc)
	if err != nil {
		return "", fmt.Errorf("cannot read %q: %w", ref.RealPath, err)
	}
	return kind, nil
}

// hardLinkTarget returns the regular file that has the contents of ref. For a
// regular file, it is ref itself. For a hard link to a lower layer, it follows
// the link, and the next ones, in the layer that added each link. It returns
// false when the target is not a regular file, or when it cannot find it.
func hardLinkTarget(img *image.Image, ref file.Reference, entry filetree.IndexEntry) (file.Reference, bool) {
	// Each link points into a lower layer, so a valid chain is shorter than
	// the number of layers.
	for range len(img.Layers) {
		if entry.Type != file.TypeHardLink {
			return ref, entry.Type == file.TypeRegular
		}
		layer := img.FileCatalog.Layer(ref)
		if layer == nil || layer.SquashedTree == nil || entry.LinkDestination == "" {
			return ref, false
		}
		target := file.Path(path.Clean(file.DirSeparator + entry.LinkDestination))
		// Without FollowBasenameLinks, the lookup returns the node of the
		// target itself, also when the target is a link.
		found, resolution, err := layer.SquashedTree.File(target)
		if err != nil || !found || !resolution.HasReference() {
			return ref, false
		}
		ref = *resolution.Reference
		if entry, err = img.FileCatalog.Get(ref); err != nil {
			return ref, false
		}
	}
	return ref, false
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
func Scan(ctx context.Context, img *image.Image, lookup []string) (*Result, error) {
	executables, err := Executables(ctx, img)
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
