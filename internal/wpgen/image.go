package wpgen

import (
	"context"
	"errors"
	"fmt"
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

func newImageCmd(g *globalOptions) *cobra.Command {
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
			return runImage(cmd.Context(), args[0], opts, g.streams(cmd.OutOrStdout(), cmd.ErrOrStderr()))
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.ContainerName, "container-name", defaultContainerName,
		"Name of the container in spec.rulesByContainer")
	flags.StringVar(
		&opts.Name,
		"name",
		"",
		"Name of the policy (default: last path element of the image repository, or \"todo\" when wpgen cannot derive it)",
	)
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

func runImage(ctx context.Context, input string, opts *imageOptions, s streams) error {
	// Validate before loading the image: a pull can take a long time.
	if err := opts.validate(); err != nil {
		return err
	}

	scanned, err := scanImage(ctx, input, &opts.scanOptions, nil, s.err)
	if err != nil {
		return err
	}

	policyName := opts.Name
	var noNameReason error
	if policyName == "" {
		policyName, err = policyNameFromImage(input, scanned.FromFile, scanned.Repositories)
		if errors.Is(err, errNoPolicyName) {
			policyName, noNameReason = placeholderPolicyName, err
		} else if err != nil {
			return err
		}
	}

	policy, err := policydraft.New(policyName, opts.Namespace, opts.Mode, map[string][]string{
		opts.ContainerName: scanned.Executables,
	})
	if err != nil {
		return err
	}
	s.separate()
	if err = policydraft.Encode(s.out, policy, opts.Output); err != nil {
		return err
	}

	fmt.Fprintln(s.err)
	printDraftSummary(s.err, s.errPainter, []draftedContainer{
		{Label: opts.ContainerName, Image: input, Scanned: scanned},
	}, opts.WarnThreshold)
	if noNameReason != nil {
		fmt.Fprintf(s.err, "\n%s %v.\nThe policy name is %q. Use --name, or edit metadata.name.\n",
			s.errPainter.warning("WARNING:"), noNameReason, placeholderPolicyName)
	}
	fmt.Fprintf(s.err, "\nAdd this label to the pod template of the workload that runs this image:\n  %s: %s\n",
		v1alpha1.PolicyLabelKey, policyName)
	if opts.ContainerName == defaultContainerName {
		fmt.Fprintf(s.err, "Make sure that the container is named %q in the pod, or use --container-name.\n",
			defaultContainerName)
	}
	return nil
}

// placeholderPolicyName is the policy name when wpgen cannot derive one, and
// the user does not give one with --name.
const placeholderPolicyName = "todo"

// errNoPolicyName is returned when the image gives no name for the policy.
var errNoPolicyName = errors.New("cannot derive the policy name")

// policyNameFromImage derives the policy name from the last path element of
// the image repository. When the image comes from a file or a directory, the
// input is a path: the repository comes from the tags stored in the image.
// Otherwise the input is an image reference, and the tags are the fallback.
// It returns errNoPolicyName when the image gives no repository.
func policyNameFromImage(input string, fromFile bool, repositories []string) (string, error) {
	var repository string
	if !fromFile {
		if ref, err := name.ParseReference(input); err == nil {
			repository = ref.Context().RepositoryStr()
		}
	}
	if repository == "" && len(repositories) > 0 {
		repository = repositories[0]
	}
	if repository == "" {
		if fromFile {
			return "", fmt.Errorf("%w from %q: the image has no tags", errNoPolicyName, input)
		}
		return "", fmt.Errorf("%w from %q: it is not an image reference, and the image has no tags",
			errNoPolicyName, input)
	}

	policyName := strings.ReplaceAll(path.Base(repository), "_", "-")
	if err := validatePolicyName(policyName); err != nil {
		return "", fmt.Errorf("%w: use --name", err)
	}
	return policyName, nil
}
