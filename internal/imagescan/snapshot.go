package imagescan

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/anchore/stereoscope/pkg/image"
)

// Snapshot is the result of Scan on an image, stored in a file with the
// inputs of the scan. Tests use snapshots of real images, so that they do not
// need the network.
type Snapshot struct {
	// Image is the reference of the scanned image. It is pinned by digest,
	// so that the snapshot does not change when the image is scanned again.
	Image string `json:"image"`
	// Platform is the platform of the scanned image, for example
	// "linux/amd64".
	Platform string `json:"platform"`
	// Lookup are the paths that the scan resolves through the symbolic links
	// of the image. They are the paths that the tests ask about.
	Lookup []string `json:"lookup"`

	Executables []Executable      `json:"executables"`
	Links       map[string]string `json:"links"`
}

// TakeSnapshot scans the image with Scan, for the lookup paths.
func TakeSnapshot(img *image.Image, ref, platform string, lookup []string) (*Snapshot, error) {
	result, err := Scan(img, lookup)
	if err != nil {
		return nil, err
	}

	lookup = slices.Sorted(slices.Values(lookup))
	return &Snapshot{
		Image:       ref,
		Platform:    platform,
		Lookup:      slices.Compact(lookup),
		Executables: result.Executables,
		Links:       result.Links,
	}, nil
}

// ReadSnapshot reads a snapshot written by Write.
func ReadSnapshot(r io.Reader) (*Snapshot, error) {
	var s Snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, fmt.Errorf("cannot read the snapshot: %w", err)
	}
	return &s, nil
}

// Write writes the snapshot as indented JSON. The map keys are sorted, so the
// output is stable.
func (s *Snapshot) Write(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(s)
}

// Result returns the result of Scan for the given lookup paths. It returns an
// error when a path is not in the lookup paths of the snapshot: the snapshot
// does not know if such a path goes through a symbolic link.
func (s *Snapshot) Result(lookup []string) (*Result, error) {
	links := map[string]string{}
	for _, p := range lookup {
		if !slices.Contains(s.Lookup, p) {
			return nil, fmt.Errorf("the snapshot of %s has no lookup path %q: "+
				"add it to the lookup paths of the snapshot and regenerate it", s.Image, p)
		}
		if target, found := s.Links[p]; found {
			links[p] = target
		}
	}
	return &Result{Executables: s.Executables, Links: links}, nil
}
