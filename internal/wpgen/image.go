package wpgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
)

const (
	defaultContainerName = "main"
	defaultNamespace     = "default"
)

type imageOptions struct {
	draftOptions

	ContainerName string
	Name          string
	Namespace     string
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
	opts.addFlags(flags)

	return cmd
}

func (o *imageOptions) validate() error {
	errs := o.draftOptions.validate()
	if err := validateDNS1123Label("container name", o.ContainerName); err != nil {
		errs = append(errs, err)
	}
	if err := validateDNS1123Label("namespace", o.Namespace); err != nil {
		errs = append(errs, err)
	}
	if o.Name != "" {
		if err := validatePolicyName(o.Name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func runImage(ctx context.Context, input string, opts *imageOptions, stdout, stderr io.Writer) error {
	// Validate before loading the image: a pull can take a long time.
	if err := opts.validate(); err != nil {
		return err
	}

	scanned, err := scanImage(ctx, input, &opts.loadOptions, nil, stderr)
	if err != nil {
		return err
	}

	policyName := opts.Name
	if policyName == "" {
		if policyName, err = policyNameFromImage(input, scanned.Repositories); err != nil {
			return err
		}
	}

	policy, err := policydraft.New(policyName, opts.Namespace, opts.Mode, map[string][]string{
		opts.ContainerName: scanned.Executables,
	})
	if err != nil {
		return err
	}
	if err = policydraft.Encode(stdout, policy, opts.Output); err != nil {
		return err
	}

	printContainerSummary(stderr, "", fmt.Sprintf("container %q", opts.ContainerName), input,
		len(scanned.Executables), opts.WarnThreshold)
	fmt.Fprintf(stderr, "Add this label to the pod template of the workload that runs this image:\n  %s: %s\n",
		v1alpha1.PolicyLabelKey, policyName)
	if opts.ContainerName == defaultContainerName {
		fmt.Fprintf(stderr, "Make sure that the container is named %q in the pod, or use --container-name.\n",
			defaultContainerName)
	}
	return nil
}

// policyNameFromImage derives the policy name from the last path element of
// the image repository. For a local archive or directory, the repository
// comes from the tags stored in the image.
func policyNameFromImage(input string, repositories []string) (string, error) {
	var repository string
	if _, statErr := os.Stat(input); statErr != nil {
		if ref, err := name.ParseReference(input); err == nil {
			repository = ref.Context().RepositoryStr()
		}
	}
	if repository == "" && len(repositories) > 0 {
		repository = repositories[0]
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
