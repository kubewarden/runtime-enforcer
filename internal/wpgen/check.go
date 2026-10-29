package wpgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
	"github.com/kubewarden/runtime-enforcer/internal/workloadparse"
)

const (
	workloadFlag      = "workload"
	imageFlag         = "image"
	containerNameFlag = "container-name"
)

type checkOptions struct {
	scanOptions

	Workload      string
	Image         string
	ContainerName string
}

// checkedContainer is a container of the policy with its image.
type checkedContainer struct {
	workloadparse.Container

	Allowed []string
}

// containerReport is the result of the check of one container.
type containerReport struct {
	checkedContainer

	// Stale are the allowed paths that are not executables in the image.
	Stale []string
	// Links maps the stale paths that are symbolic links to their real path.
	Links map[string]string
	// Libraries are the allowed paths that are shared libraries, when the
	// scan options skip them.
	Libraries []string
	// Unknown are the allowed paths that are neither programs nor scripts,
	// when the scan options skip them.
	Unknown []string
	// NotAllowed is the number of executables of the image that the policy
	// does not allow.
	NotAllowed int
}

func newCheckCmd() *cobra.Command {
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
executables of the image, so this count is not a problem.

When an allowed path is a symbolic link in the image, wpgen shows its real
path. The enforcer reports the real path, so the policy must allow it.

The exit code is 1 when at least one allowed path is not an executable in
the image. This happens after an image update that removes a file. It also
happens for a path on a volume or in a foreign root: keep these paths in the
policy if the workload needs them.

The report goes to standard output. Other messages go to standard error.`,
		Example: `  # Compare a policy with the images of a Deployment
  wpgen check ./policy.yaml --workload ./deploy/nginx.yaml

  # Compare a policy with a single image
  wpgen check ./policy.yaml --image ghcr.io/example/api:2.3.0 --container-name api`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cmd.Context(), args[0], opts, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.Workload, workloadFlag, "",
		`File with the workload that uses the policy ("-" for standard input)`)
	flags.StringVar(&opts.Image, imageFlag, "",
		"Image of one container of the policy")
	flags.StringVar(&opts.ContainerName, containerNameFlag, "",
		"Container of the policy that runs --image (default: the only container of the policy)")
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
	return errors.Join(errs...)
}

func runCheck(
	ctx context.Context,
	policyFile string,
	opts *checkOptions,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	if err := opts.validate(policyFile); err != nil {
		return err
	}

	policy, err := readPolicy(policyFile, stdin, stderr)
	if err != nil {
		return err
	}

	var containers []checkedContainer
	if opts.Image != "" {
		containers, err = imageContainers(policy, opts.Image, opts.ContainerName)
	} else {
		containers, err = workloadContainers(policy, opts.Workload, stdin, stderr)
	}
	if err != nil {
		return err
	}

	reports, err := checkContainers(ctx, containers, &opts.scanOptions, stderr)
	if err != nil {
		return err
	}

	return printCheckReport(stdout, policy, reports)
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

func allowedPaths(rules *v1alpha1.WorkloadPolicyRules) []string {
	if rules == nil {
		return nil
	}
	return rules.Executables.Allowed
}

// imageContainers returns the container of the policy that runs the image.
func imageContainers(policy *v1alpha1.WorkloadPolicy, imageRef, containerName string) ([]checkedContainer, error) {
	if containerName == "" {
		if len(policy.Spec.RulesByContainer) != 1 {
			return nil, fmt.Errorf("the policy has %d containers, use --%s to choose one",
				len(policy.Spec.RulesByContainer), containerNameFlag)
		}
		for name := range policy.Spec.RulesByContainer {
			containerName = name
		}
	}

	rules, found := policy.Spec.RulesByContainer[containerName]
	if !found {
		return nil, fmt.Errorf("the policy has no container %q", containerName)
	}
	return []checkedContainer{{
		Name:    containerName,
		Image:   imageRef,
		Allowed: allowedPaths(rules),
	}}, nil
}

// workloadContainers returns the containers that are both in the policy and
// in the one workload of the file. It prints a notice for the containers
// that are only in one of them.
func workloadContainers(
	policy *v1alpha1.WorkloadPolicy,
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
	workload := workloads[0]

	var containers []checkedContainer
	inWorkload := map[string]bool{}
	for _, c := range workload.Containers {
		inWorkload[c.Name] = true
		rules, found := policy.Spec.RulesByContainer[c.Name]
		if !found {
			fmt.Fprintf(
				stderr,
				"The policy has no rules for container %q of %s %q\n",
				c.Name,
				workload.Kind,
				workload.Name,
			)
			continue
		}
		containers = append(containers, checkedContainer{Container: c, Allowed: allowedPaths(rules)})
	}

	policyContainers := make([]string, 0, len(policy.Spec.RulesByContainer))
	for name := range policy.Spec.RulesByContainer {
		policyContainers = append(policyContainers, name)
	}
	slices.Sort(policyContainers)
	for _, name := range policyContainers {
		if !inWorkload[name] {
			fmt.Fprintf(stderr, "The policy has rules for container %q, which is not in %s %q\n",
				name, workload.Kind, workload.Name)
		}
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("the policy and %s %q have no container in common", workload.Kind, workload.Name)
	}
	return containers, nil
}

// checkContainers scans each image once and compares it with the allowed
// paths of the containers that use it.
func checkContainers(
	ctx context.Context,
	containers []checkedContainer,
	opts *scanOptions,
	stderr io.Writer,
) ([]containerReport, error) {
	var images []string
	lookup := map[string][]string{}
	for _, c := range containers {
		if _, found := lookup[c.Image]; !found {
			images = append(images, c.Image)
		}
		lookup[c.Image] = append(lookup[c.Image], c.Allowed...)
	}

	scanned := map[string]*scannedImage{}
	for _, imageRef := range images {
		s, err := scanImage(ctx, imageRef, opts, lookup[imageRef], stderr)
		if err != nil {
			return nil, err
		}
		scanned[imageRef] = s
	}

	reports := make([]containerReport, 0, len(containers))
	for _, c := range containers {
		reports = append(reports, compare(c, scanned[c.Image]))
	}
	return reports, nil
}

func compare(c checkedContainer, s *scannedImage) containerReport {
	report := containerReport{checkedContainer: c, Links: map[string]string{}}

	allowed := map[string]bool{}
	for _, p := range c.Allowed {
		if allowed[p] {
			continue
		}
		allowed[p] = true
		if _, found := slices.BinarySearch(s.Executables, p); found {
			continue
		}
		switch s.Skipped[p] {
		case imagescan.KindLibrary:
			report.Libraries = append(report.Libraries, p)
			continue
		case imagescan.KindUnknown:
			report.Unknown = append(report.Unknown, p)
			continue
		case imagescan.KindProgram, imagescan.KindScript:
		}
		report.Stale = append(report.Stale, p)
		if target, isLink := s.Links[p]; isLink {
			report.Links[p] = target
		}
	}
	slices.Sort(report.Stale)
	slices.Sort(report.Libraries)
	slices.Sort(report.Unknown)

	for _, p := range s.Executables {
		if !allowed[p] {
			report.NotAllowed++
		}
	}
	report.Allowed = slices.Sorted(maps.Keys(allowed))
	return report
}

// printSkippedPaths lists the allowed paths of a kind that the scan options
// skip. They are not stale: the files exist and have an execute bit.
func printSkippedPaths(w io.Writer, paths []string, what, flag string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintf(w, "    %d allowed paths are %s, which wpgen skips unless --%s is set:\n", len(paths), what, flag)
	for _, p := range paths {
		fmt.Fprintf(w, "      %s\n", p)
	}
}

func printCheckReport(w io.Writer, policy *v1alpha1.WorkloadPolicy, reports []containerReport) error {
	namespace := policy.Namespace
	if namespace == "" {
		namespace = "<none>"
	}
	fmt.Fprintf(w, "Policy %q (namespace %s):\n", policy.Name, namespace)

	stale := 0
	for _, r := range reports {
		label := fmt.Sprintf("container %q", r.Name)
		if r.Init {
			label = "init " + label
		}
		fmt.Fprintf(w, "  %s (image %s):\n", label, r.Image)

		allowed := len(r.Allowed)
		if notExecutables := len(r.Stale) + len(r.Libraries) + len(r.Unknown); notExecutables == 0 {
			fmt.Fprintf(w, "    all %d allowed paths are executables in the image\n", allowed)
		} else {
			fmt.Fprintf(w, "    %d of %d allowed paths are executables in the image\n", allowed-notExecutables, allowed)
		}
		if len(r.Stale) > 0 {
			fmt.Fprintf(w, "    %d allowed paths are not executables in the image:\n", len(r.Stale))
			for _, p := range r.Stale {
				if target, isLink := r.Links[p]; isLink {
					fmt.Fprintf(w, "      %s (symbolic link to %s, the enforcer reports %s)\n", p, target, target)
					continue
				}
				fmt.Fprintf(w, "      %s\n", p)
			}
		}
		printSkippedPaths(w, r.Libraries, "shared libraries", includeLibrariesFlag)
		printSkippedPaths(w, r.Unknown, "neither programs nor scripts", includeUnknownFlag)
		fmt.Fprintf(w, "    %d executables of the image are not allowed\n", r.NotAllowed)
		stale += len(r.Stale)
	}

	if stale > 0 {
		return fmt.Errorf("%d allowed paths are not executables in the images", stale)
	}
	return nil
}
