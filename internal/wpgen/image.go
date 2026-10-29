package wpgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

const (
	defaultContainerName = "main"
	defaultNamespace     = "default"
	defaultWarnThreshold = 50
)

type imageOptions struct {
	ContainerName string
	Name          string
	Namespace     string
	Mode          string
	Platform      string
	Output        string
	Sources       []string
	WarnThreshold int
}

func newImageCmd() *cobra.Command {
	opts := &imageOptions{}

	cmd := &cobra.Command{
		Use:   "image IMAGE",
		Short: "Draft a WorkloadPolicy from a single container image",
		Long: `Draft a WorkloadPolicy from a single container image.

The policy has one container. wpgen treats the image as the main container
of the pod. The policy allows every regular file of the image that has an
execute permission bit set.

wpgen looks for the image in the sources given by --image-src, in order, and
uses the first source that has it. A daemon source (docker, podman) pulls the
image into the daemon when the daemon does not have it.

The policy goes to standard output. Messages go to standard error.`,
		Example: `  # Draft a policy for the main container of a pod
  wpgen image docker.io/library/nginx:1.27

  # Choose the container name, the policy name and the namespace
  wpgen image ghcr.io/example/api:2.3.0 --container-name api --name api --namespace prod

  # Always read the image from the registry
  wpgen image ghcr.io/example/api:2.3.0 --image-src registry`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImage(cmd.Context(), args[0], opts, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.ContainerName, "container-name", defaultContainerName,
		"Name of the container in spec.rulesByContainer")
	flags.StringVar(&opts.Name, "name", "",
		"Name of the policy (default: last path element of the image repository)")
	flags.StringVar(&opts.Namespace, "namespace", defaultNamespace,
		"Namespace of the policy")
	flags.StringVar(&opts.Mode, "mode", policymode.MonitorString,
		fmt.Sprintf("Policy mode (%s or %s)", policymode.MonitorString, policymode.ProtectString))
	flags.StringVar(&opts.Platform, "platform", "linux/"+runtime.GOARCH,
		"Platform to select from a multi-platform image")
	flags.StringVarP(&opts.Output, "output", "o", policydraft.FormatYAML,
		fmt.Sprintf("Output format (%s or %s)", policydraft.FormatYAML, policydraft.FormatJSON))
	flags.StringSliceVar(&opts.Sources, "image-src", imagescan.DefaultSources,
		fmt.Sprintf("Image sources to try, in order. Valid values: %s", strings.Join(imagescan.KnownSources(), ", ")))
	flags.IntVar(&opts.WarnThreshold, "warn-threshold", defaultWarnThreshold,
		"Print a warning when the policy allows more executables than this value (0 disables the warning)")

	return cmd
}

func (o *imageOptions) validate() error {
	var errs []error
	if msgs := validation.IsDNS1123Label(o.ContainerName); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("invalid container name %q: %s", o.ContainerName, strings.Join(msgs, ", ")))
	}
	if msgs := validation.IsDNS1123Label(o.Namespace); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("invalid namespace %q: %s", o.Namespace, strings.Join(msgs, ", ")))
	}
	if o.Name != "" {
		if err := validatePolicyName(o.Name); err != nil {
			errs = append(errs, err)
		}
	}
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
	if err := imagescan.ValidateSources(o.Sources); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func runImage(ctx context.Context, input string, opts *imageOptions, stdout, stderr io.Writer) error {
	// Validate before loading the image: a pull can take a long time.
	if err := opts.validate(); err != nil {
		return err
	}

	fmt.Fprintf(stderr, "Loading image %q...\n", input)
	img, err := imagescan.Load(ctx, input, imagescan.LoadOptions{
		Sources:  opts.Sources,
		Platform: opts.Platform,
	})
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := img.Cleanup(); cleanupErr != nil {
			fmt.Fprintf(stderr, "WARNING: cannot remove the temporary files of the image: %v\n", cleanupErr)
		}
	}()
	fmt.Fprintf(stderr, "Loaded image %q from source %q (%s)\n", input, img.Source, imagePlatform(img))

	policyName := opts.Name
	if policyName == "" {
		if policyName, err = policyNameFromImage(input, img); err != nil {
			return err
		}
	}

	executables, err := imagescan.Executables(img.Image)
	if err != nil {
		return fmt.Errorf("cannot list the executables of image %q: %w", input, err)
	}

	policy, err := policydraft.New(policyName, opts.Namespace, opts.Mode, map[string][]string{
		opts.ContainerName: executables,
	})
	if err != nil {
		return err
	}
	if err = policydraft.Encode(stdout, policy, opts.Output); err != nil {
		return err
	}

	printSummary(stderr, input, opts, policyName, len(executables))
	return nil
}

func printSummary(w io.Writer, input string, opts *imageOptions, policyName string, count int) {
	noun := "executables"
	if count == 1 {
		noun = "executable"
	}
	fmt.Fprintf(w, "container %q (image %s): %d %s\n", opts.ContainerName, input, count, noun)
	if opts.WarnThreshold > 0 && count > opts.WarnThreshold {
		fmt.Fprintf(w, "WARNING: container %q allows %d executables. A learned policy is usually\n"+
			"much smaller. Review the list before you switch the policy to protect mode.\n",
			opts.ContainerName, count)
	}
	fmt.Fprintf(w, "Add this label to the pod template of the workload that runs this image:\n  %s: %s\n",
		v1alpha1.PolicyLabelKey, policyName)
	if opts.ContainerName == defaultContainerName {
		fmt.Fprintf(w, "Make sure that the container is named %q in the pod, or use --container-name.\n",
			defaultContainerName)
	}
}

func imagePlatform(img *imagescan.Image) string {
	p := img.Metadata.OS + "/" + img.Metadata.Architecture
	if img.Metadata.Variant != "" {
		p += "/" + img.Metadata.Variant
	}
	return p
}

// policyNameFromImage derives the policy name from the last path element of
// the image repository. For a local archive or directory, the repository
// comes from the tags stored in the image.
func policyNameFromImage(input string, img *imagescan.Image) (string, error) {
	var repository string
	if _, statErr := os.Stat(input); statErr != nil {
		if ref, err := name.ParseReference(input); err == nil {
			repository = ref.Context().RepositoryStr()
		}
	}
	if repository == "" && len(img.Metadata.Tags) > 0 {
		repository = img.Metadata.Tags[0].RepositoryStr()
	}
	if repository == "" {
		return "", fmt.Errorf("cannot derive the policy name from %q: use --name", input)
	}

	policyName := strings.ReplaceAll(path.Base(repository), "_", "-")
	if err := validatePolicyName(policyName); err != nil {
		return "", fmt.Errorf("%w: use --name", err)
	}
	return policyName, nil
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
