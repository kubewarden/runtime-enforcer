// Package imagescan loads container images and lists the executable files
// they contain.
package imagescan

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/go-collections"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
)

// DefaultSources is the order used to look for an image when the user does
// not provide one. Local archives come first, then the local daemons, and
// finally the remote registry.
//
//nolint:gochecknoglobals // read-only default exposed to the CLI.
var DefaultSources = []string{
	stereoscope.FileTag,
	image.DockerDaemonSource,
	image.PodmanDaemonSource,
	stereoscope.RegistryTag,
}

// LoadOptions tunes how an image is loaded.
type LoadOptions struct {
	// Sources are the stereoscope provider names or tags to try, in order.
	// The first source that returns the image wins.
	Sources []string
	// Platform selects one image of a multi-platform index, for example
	// "linux/arm64". Empty means the stereoscope default.
	Platform string
}

// Image is a loaded container image. Call Cleanup when done with it.
type Image struct {
	*image.Image

	// Source is the entry of LoadOptions.Sources that provided the image.
	Source string
}

// Cleanup removes the temporary files created while loading the image.
func (i *Image) Cleanup() error {
	if i == nil || i.Image == nil {
		return nil
	}
	return i.Image.Cleanup()
}

// KnownSources returns every provider name and tag that stereoscope accepts.
func KnownSources() []string {
	tags := providers().Tags()
	slices.Sort(tags)
	return tags
}

// IsFileSource reports if every provider of the source reads an image from
// a file or a directory, for example an archive made by "docker save". The
// name of such an image is a path, not an image reference.
func IsFileSource(source string) bool {
	selected := providers().Select(source)
	return len(selected) > 0 && len(selected.Remove(stereoscope.FileTag)) == 0
}

// providers returns the providers of stereoscope with their tags, without
// the providers that the wpgen binary does not include.
//
// The containers-storage provider needs the containers_image_openpgp build
// tag, and the libraries of containers/image and containers/storage. wpgen is
// built without them, so stereoscope only has a stub that always fails.
func providers() collections.TaggedValueSet[image.Provider] {
	return collections.TaggedValueSet[image.Provider]{}.
		Join(stereoscope.ImageProviders(stereoscope.ImageProviderConfig{})...).
		Remove(image.ContainersStorageSource)
}

// ValidateSources returns an error when one of the sources is unknown.
func ValidateSources(sources []string) error {
	if len(sources) == 0 {
		return errors.New("at least one image source is required")
	}
	known := KnownSources()
	for _, s := range sources {
		if !slices.Contains(known, s) {
			return fmt.Errorf("unknown image source %q, valid values: %s", s, strings.Join(known, ", "))
		}
	}
	return nil
}

// Load resolves the user input to an image. It tries each source in order
// and returns the first image found. When every source fails, the returned
// error contains the error of each source.
//
// When opts.Platform is set, an image of another platform is a failure of
// its source. Most sources of stereoscope check the platform themselves,
// but not all of them: the Docker archive source ignores it.
func Load(ctx context.Context, input string, opts LoadOptions) (*Image, error) {
	sources := opts.Sources
	if len(sources) == 0 {
		sources = DefaultSources
	}
	if err := ValidateSources(sources); err != nil {
		return nil, err
	}

	var (
		stereoOpts []stereoscope.Option
		platform   *image.Platform
	)
	if opts.Platform != "" {
		var err error
		if platform, err = image.NewPlatform(opts.Platform); err != nil {
			return nil, fmt.Errorf("invalid platform: %w", err)
		}
		stereoOpts = append(stereoOpts, stereoscope.WithPlatform(opts.Platform))
	}

	var errs []error
	for _, source := range sources {
		img, err := stereoscope.GetImageFromSource(ctx, input, source, stereoOpts...)
		if err == nil && platform != nil {
			if err = checkPlatform(img, platform); err != nil {
				err = errors.Join(err, img.Cleanup())
			}
		}
		if err == nil {
			return &Image{Image: img, Source: source}, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", source, err))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
	}

	return nil, fmt.Errorf("cannot load image %q: %w", input, errors.Join(errs...))
}

// checkPlatform returns an error when the platform of the image is not the
// wanted one. The variant must match only when the wanted platform has one,
// as in stereoscope. An image without a platform in its configuration does
// not match.
func checkPlatform(img *image.Image, want *image.Platform) error {
	declared := image.Platform{
		OS:           img.Metadata.OS,
		Architecture: img.Metadata.Architecture,
		Variant:      img.Metadata.Variant,
	}
	got, err := image.NewPlatform(declared.String())
	if err == nil && got.OS == want.OS && got.Architecture == want.Architecture &&
		(want.Variant == "" || got.Variant == want.Variant) {
		return nil
	}
	return &image.ErrPlatformMismatch{
		ExpectedPlatform: want.String(),
		Err:              fmt.Errorf("image platform=%q", declared.String()),
	}
}

// CleanupAll removes the root temporary directory of stereoscope. Call it
// once, after all the images are cleaned up, before the program exits.
//
// Image.Cleanup only removes the files of a loaded image. When a source
// fails, stereoscope can leave an empty directory behind, and no Image
// exists to remove it.
func CleanupAll() {
	//nolint:staticcheck // Image.Cleanup does not cover the failed loads, see above.
	stereoscope.Cleanup()
}
