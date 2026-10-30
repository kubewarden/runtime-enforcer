package wpgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
)

const (
	workloadFlag       = "workload"
	imageFlag          = "image"
	containerNameFlag  = "container-name"
	listNotAllowedFlag = "list-not-allowed"

	outputTable = "table"
	outputJSON  = "json"
)

type checkOptions struct {
	scanOptions

	Workload       string
	Image          string
	ContainerName  string
	Output         string
	ListNotAllowed bool
}

func newCheckCmd(g *globalOptions) *cobra.Command {
	opts := &checkOptions{}

	cmd := &cobra.Command{
		Use:   "check POLICY_FILE (--workload FILE | --image IMAGE)",
		Short: "Compare a WorkloadPolicy with the images of a workload",
		Long: `Compare a WorkloadPolicy with the images of a workload.

POLICY_FILE has one WorkloadPolicy or one WorkloadPolicyProposal. Use "-" to
read from standard input. The images come from the one workload of the file
given with --workload, or from --image.

For each container of the policy, wpgen lists the allowed paths that are not
executables in the image, and counts the executables of the image that the
policy does not allow. A learned policy usually does not allow most of the
executables of the image, so this count is not a problem. Use
--list-not-allowed to list them.

When an allowed path is a symbolic link in the image, wpgen shows its real
path. The enforcer reports the real path, so the policy must allow it.

The exit code is 1 when at least one allowed path is not an executable in
the image. This happens after an image update that removes a file. It also
happens for a path on a volume or in a foreign root: keep these paths in the
policy if the workload needs them.

The exit code is also 1 when a container of the workload has no rules in the
policy, for example a new container. The enforcer does not protect such a
container.

The report goes to standard output, as a table or as JSON. Other messages go
to standard error. The last lines on standard error are the verdict. They
also count the allowed paths that wpgen skipped, and the containers of the
policy that it did not check.`,
		Example: `  # Compare a policy with the images of a Deployment
  wpgen check ./policy.yaml --workload ./deploy/nginx.yaml

  # Compare a policy with a single image
  wpgen check ./policy.yaml --image ghcr.io/example/api:2.3.0 --container-name api

  # Write the report as JSON, with the executables that the policy does not allow
  wpgen check ./policy.yaml --workload ./deploy/nginx.yaml -o json --list-not-allowed`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd.Context(), args[0], opts, newContextReader(cmd.Context(), cmd.InOrStdin()),
				g.streams(cmd.OutOrStdout(), cmd.ErrOrStderr()))
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.Workload, workloadFlag, "",
		`File with the workload that uses the policy ("-" for standard input)`)
	flags.StringVar(&opts.Image, imageFlag, "",
		"Image of one container of the policy")
	flags.StringVar(&opts.ContainerName, containerNameFlag, "",
		"Container of the policy that runs --image (default: the only container of the policy)")
	flags.StringVarP(&opts.Output, "output", "o", outputTable,
		fmt.Sprintf("Report format (%s or %s)", outputTable, outputJSON))
	flags.BoolVar(&opts.ListNotAllowed, listNotAllowedFlag, false,
		"List the executables of the image that the policy does not allow, not only their number")
	opts.addFlags(flags)

	cmd.MarkFlagsMutuallyExclusive(workloadFlag, imageFlag)
	cmd.MarkFlagsOneRequired(workloadFlag, imageFlag)

	return cmd
}

func (o *checkOptions) validate(policyFile string) error {
	errs := o.scanOptions.validate()
	if o.ContainerName != "" && o.Image == "" {
		errs = append(errs, fmt.Errorf("--%s needs --%s", containerNameFlag, imageFlag))
	}
	if policyFile == stdinFile && o.Workload == stdinFile {
		errs = append(errs, errors.New("the policy and the workload cannot both come from standard input"))
	}
	if o.Output != outputTable && o.Output != outputJSON {
		errs = append(errs, fmt.Errorf("invalid output format %q: must be %q or %q", o.Output, outputTable, outputJSON))
	}
	return errors.Join(errs...)
}

func runCheck(
	ctx context.Context,
	policyFile string,
	opts *checkOptions,
	stdin io.Reader,
	s streams,
) error {
	if err := opts.validate(policyFile); err != nil {
		return err
	}

	policy, err := readPolicy(policyFile, stdin, s.err)
	if err != nil {
		return err
	}

	result := &checkResult{Policy: policy}
	var containers []checkedContainer
	if opts.Image != "" {
		containers, err = imageContainers(policy, opts.Image, opts.ContainerName)
	} else {
		containers, err = workloadContainers(result, opts.Workload, stdin, s.err)
	}
	if err != nil {
		return err
	}
	printMismatches(s.err, s.errPainter, result)

	if result.Containers, err = checkContainers(ctx, containers, &opts.scanOptions, s.err); err != nil {
		return err
	}

	s.separate()
	if opts.Output == outputJSON {
		err = renderCheckJSON(s.out, result, opts.ListNotAllowed)
	} else {
		err = renderCheckTable(s.out, s.outPainter, result, opts.ListNotAllowed)
	}
	if err != nil {
		return err
	}

	return printVerdict(s.err, s.errPainter, result)
}

func readPolicy(file string, stdin io.Reader, stderr io.Writer) (*v1alpha1.WorkloadPolicy, error) {
	r := stdin
	if file != stdinFile {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	policies, skipped, err := policydraft.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", file, err)
	}
	for _, s := range skipped {
		fmt.Fprintf(stderr, "Skipping %s %q (%s): not a policy\n", s.Kind, s.Name, s.APIVersion)
	}
	if len(policies) != 1 {
		return nil, fmt.Errorf("%s must have exactly one WorkloadPolicy or WorkloadPolicyProposal, found %d",
			file, len(policies))
	}
	return policies[0], nil
}

// workloadContainers returns the containers that are both in the policy and
// in the one workload of the file. It records the workload, and the
// containers that are only in one of them, in the result.
func workloadContainers(
	result *checkResult,
	file string,
	stdin io.Reader,
	stderr io.Writer,
) ([]checkedContainer, error) {
	workloads, err := readWorkloads(file, stdin, stderr)
	if err != nil {
		return nil, err
	}
	if len(workloads) != 1 {
		names := make([]string, 0, len(workloads))
		for _, w := range workloads {
			names = append(names, fmt.Sprintf("%s %q", w.Kind, w.Name))
		}
		return nil, fmt.Errorf("%s must have exactly one workload, found %s", file, strings.Join(names, ", "))
	}
	return matchContainers(result, workloads[0])
}
