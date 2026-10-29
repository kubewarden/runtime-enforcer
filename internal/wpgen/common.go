package wpgen

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

const defaultWarnThreshold = 50

const (
	includeLibrariesFlag = "include-libraries"
	includeUnknownFlag   = "include-unknown"
)

// scanOptions are the flags of all the commands that scan images.
type scanOptions struct {
	Platform         string
	Sources          []string
	IncludeLibraries bool
	IncludeUnknown   bool
}

func (o *scanOptions) addFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.Platform, "platform", "",
		"Platform to select from a multi-platform image (default: linux/<host architecture>)")
	flags.StringSliceVar(&o.Sources, "image-src", imagescan.DefaultSources,
		fmt.Sprintf("Image sources to try, in order. Valid values: %s", strings.Join(imagescan.KnownSources(), ", ")))
	flags.BoolVar(&o.IncludeLibraries, includeLibrariesFlag, false,
		"Count ELF shared libraries as executables. Programs load them, but do not run them")
	flags.BoolVar(
		&o.IncludeUnknown,
		includeUnknownFlag,
		false,
		"Count files that are neither ELF programs nor scripts as executables, for example data files with an execute bit",
	)
}

// includes reports if the executables of this kind count as executables.
func (o *scanOptions) includes(kind imagescan.Kind) bool {
	switch kind {
	case imagescan.KindProgram, imagescan.KindScript:
		return true
	case imagescan.KindLibrary:
		return o.IncludeLibraries
	case imagescan.KindUnknown:
		return o.IncludeUnknown
	default:
		return true
	}
}

// platform returns the platform given by the user, or linux with the
// architecture of the host. The default is resolved here, and not in the flag
// definition, so that the help text is the same on all hosts.
func (o *scanOptions) platform() string {
	if o.Platform != "" {
		return o.Platform
	}
	return "linux/" + runtime.GOARCH
}

func (o *scanOptions) validate() []error {
	if err := imagescan.ValidateSources(o.Sources); err != nil {
		return []error{err}
	}
	return nil
}

// draftOptions are the flags of the commands that draft a policy.
type draftOptions struct {
	scanOptions

	Mode          string
	Output        string
	WarnThreshold int
}

func (o *draftOptions) addFlags(flags *pflag.FlagSet) {
	o.scanOptions.addFlags(flags)
	flags.StringVar(&o.Mode, "mode", policymode.MonitorString,
		fmt.Sprintf("Policy mode (%s or %s)", policymode.MonitorString, policymode.ProtectString))
	flags.StringVarP(&o.Output, "output", "o", policydraft.FormatYAML,
		fmt.Sprintf("Output format (%s or %s)", policydraft.FormatYAML, policydraft.FormatJSON))
	flags.IntVar(&o.WarnThreshold, "warn-threshold", defaultWarnThreshold,
		"Print a warning when a container allows more executables than this value (0 disables the warning)")
}

func (o *draftOptions) validate() []error {
	errs := o.scanOptions.validate()
	if !policymode.IsValid(o.Mode) {
		errs = append(errs, fmt.Errorf("invalid mode %q: must be %q or %q",
			o.Mode, policymode.MonitorString, policymode.ProtectString))
	}
	if o.Output != policydraft.FormatYAML && o.Output != policydraft.FormatJSON {
		errs = append(errs, fmt.Errorf("invalid output format %q: must be %q or %q",
			o.Output, policydraft.FormatYAML, policydraft.FormatJSON))
	}
	if o.WarnThreshold < 0 {
		errs = append(errs, fmt.Errorf("invalid warn threshold %d: must be 0 or more", o.WarnThreshold))
	}
	return errs
}

// scannedImage is the result of the scan of one image.
type scannedImage struct {
	// Executables are the sorted paths of the executables of the kinds that
	// the scan options include.
	Executables []string
	// Skipped maps the paths of the other executables to their kind.
	Skipped map[string]imagescan.Kind
	// Repositories are the repositories of the tags stored in the image, when
	// the source provides them.
	Repositories []string
	// Links maps the looked up paths that go through a symbolic link to
	// their real path.
	Links map[string]string
}

// scanImage loads the image, lists its executables and removes the
// temporary files of the image before it returns. The lookup paths that are
// not executables are resolved through the symbolic links of the image.
func scanImage(
	ctx context.Context,
	input string,
	opts *scanOptions,
	lookup []string,
	stderr io.Writer,
) (*scannedImage, error) {
	fmt.Fprintf(stderr, "Loading image %q...\n", input)
	img, err := imagescan.Load(ctx, input, imagescan.LoadOptions{
		Sources:  opts.Sources,
		Platform: opts.platform(),
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := img.Cleanup(); cleanupErr != nil {
			fmt.Fprintf(stderr, "WARNING: cannot remove the temporary files of the image: %v\n", cleanupErr)
		}
	}()
	fmt.Fprintf(stderr, "Loaded image %q from source %q (%s)\n", input, img.Source, imagePlatform(img.Metadata))

	all, err := imagescan.Executables(img.Image)
	if err != nil {
		return nil, fmt.Errorf("cannot list the executables of image %q: %w", input, err)
	}
	executables := make([]string, 0, len(all))
	skipped := map[string]imagescan.Kind{}
	for _, e := range all {
		if opts.includes(e.Kind) {
			executables = append(executables, e.Path)
		} else {
			skipped[e.Path] = e.Kind
		}
	}

	var notExecutable []string
	for _, p := range lookup {
		if _, found := slices.BinarySearch(executables, p); !found {
			notExecutable = append(notExecutable, p)
		}
	}
	links, err := imagescan.ResolveLinks(img.Image, notExecutable)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the paths of image %q: %w", input, err)
	}

	repositories := make([]string, 0, len(img.Metadata.Tags))
	for _, tag := range img.Metadata.Tags {
		repositories = append(repositories, tag.RepositoryStr())
	}
	return &scannedImage{
		Executables:  executables,
		Skipped:      skipped,
		Repositories: repositories,
		Links:        links,
	}, nil
}

// skippedCount returns the number of skipped executables of the kind.
func (s *scannedImage) skippedCount(kind imagescan.Kind) int {
	n := 0
	for _, k := range s.Skipped {
		if k == kind {
			n++
		}
	}
	return n
}

func imagePlatform(md image.Metadata) string {
	p := md.OS + "/" + md.Architecture
	if md.Variant != "" {
		p += "/" + md.Variant
	}
	return p
}

// printContainerSummary prints the number of executables of a container,
// the number of skipped files, and a warning when the number of executables
// is above the threshold.
func printContainerSummary(w io.Writer, prefix, label, imageRef string, s *scannedImage, warnThreshold int) {
	count := len(s.Executables)
	fmt.Fprintf(w, "%s%s (image %s): %s\n", prefix, label, imageRef, plural(count, "executable", "executables"))
	if n := s.skippedCount(imagescan.KindLibrary); n > 0 {
		fmt.Fprintf(w, "%sskipped %s, use --%s to keep them\n",
			prefix, plural(n, "shared library", "shared libraries"), includeLibrariesFlag)
	}
	if n := s.skippedCount(imagescan.KindUnknown); n > 0 {
		fmt.Fprintf(w, "%sskipped %s, use --%s to keep them\n", prefix,
			plural(n, "file that is not a program or a script", "files that are not programs or scripts"),
			includeUnknownFlag)
	}
	if warnThreshold > 0 && count > warnThreshold {
		fmt.Fprintf(w, "%sWARNING: %s allows %d executables. A learned policy is usually\n"+
			"%smuch smaller. Review the list before you switch the policy to protect mode.\n",
			prefix, label, count, prefix)
	}
}

// plural returns the number followed by the singular or the plural noun.
func plural(n int, singular, pluralNoun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralNoun)
}

// validatePolicyName makes sure that the name is a valid object name, and
// that it can be the value of the policy label of a pod.
func validatePolicyName(policyName string) error {
	msgs := validation.IsDNS1123Subdomain(policyName)
	msgs = append(msgs, validation.IsValidLabelValue(policyName)...)
	if len(msgs) > 0 {
		return fmt.Errorf("invalid policy name %q: %s", policyName, strings.Join(msgs, ", "))
	}
	return nil
}

func validateDNS1123Label(what, value string) error {
	if msgs := validation.IsDNS1123Label(value); len(msgs) > 0 {
		return fmt.Errorf("invalid %s %q: %s", what, value, strings.Join(msgs, ", "))
	}
	return nil
}
