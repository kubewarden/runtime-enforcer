package wpgen

import (
	"context"
	"encoding/json"
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
	workloadFlag       = "workload"
	imageFlag          = "image"
	containerNameFlag  = "container-name"
	listNotAllowedFlag = "list-not-allowed"

	outputText = "text"
	outputJSON = "json"
)

type checkOptions struct {
	scanOptions

	Workload       string
	Image          string
	ContainerName  string
	Output         string
	ListNotAllowed bool
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
	// Executables are the allowed paths that are executables in the image.
	Executables []string
	// NotAllowed are the executables of the image that the policy does not
	// allow.
	NotAllowed []string
}

// checkResult is the result of the check of a policy.
type checkResult struct {
	Policy     *v1alpha1.WorkloadPolicy
	Containers []containerReport
	// OnlyInPolicy are the containers of the policy that are not in the
	// workload.
	OnlyInPolicy []string
	// OnlyInWorkload are the containers of the workload that are not in the
	// policy.
	OnlyInWorkload []string
}

// stale returns the number of stale paths of all the containers.
func (r *checkResult) stale() int {
	n := 0
	for _, c := range r.Containers {
		n += len(c.Stale)
	}
	return n
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
executables of the image, so this count is not a problem. Use
--list-not-allowed to list them.

When an allowed path is a symbolic link in the image, wpgen shows its real
path. The enforcer reports the real path, so the policy must allow it.

The exit code is 1 when at least one allowed path is not an executable in
the image. This happens after an image update that removes a file. It also
happens for a path on a volume or in a foreign root: keep these paths in the
policy if the workload needs them.

The report goes to standard output, as text or as JSON. Other messages go to
standard error.`,
		Example: `  # Compare a policy with the images of a Deployment
  wpgen check ./policy.yaml --workload ./deploy/nginx.yaml

  # Compare a policy with a single image
  wpgen check ./policy.yaml --image ghcr.io/example/api:2.3.0 --container-name api

  # Write the report as JSON, with the executables that the policy does not allow
  wpgen check ./policy.yaml --workload ./deploy/nginx.yaml -o json --list-not-allowed`,
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
	flags.StringVarP(&opts.Output, "output", "o", outputText,
		fmt.Sprintf("Output format (%s or %s)", outputText, outputJSON))
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
	if o.Output != outputText && o.Output != outputJSON {
		errs = append(errs, fmt.Errorf("invalid output format %q: must be %q or %q", o.Output, outputText, outputJSON))
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

	result := &checkResult{Policy: policy}
	var containers []checkedContainer
	if opts.Image != "" {
		containers, err = imageContainers(policy, opts.Image, opts.ContainerName)
	} else {
		containers, err = workloadContainers(result, opts.Workload, stdin, stderr)
	}
	if err != nil {
		return err
	}

	if result.Containers, err = checkContainers(ctx, containers, &opts.scanOptions, stderr); err != nil {
		return err
	}

	if opts.Output == outputJSON {
		err = renderCheckJSON(stdout, result, opts.ListNotAllowed)
	} else {
		renderCheckText(stdout, result, opts.ListNotAllowed)
	}
	if err != nil {
		return err
	}

	if stale := result.stale(); stale > 0 {
		return fmt.Errorf("%d allowed paths are not executables in the images", stale)
	}
	return nil
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
// in the one workload of the file. It records the containers that are only
// in one of them in the result, and prints a notice for each one.
func workloadContainers(
	result *checkResult,
	file string,
	stdin io.Reader,
	stderr io.Writer,
) ([]checkedContainer, error) {
	policy := result.Policy
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
			result.OnlyInWorkload = append(result.OnlyInWorkload, c.Name)
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
			result.OnlyInPolicy = append(result.OnlyInPolicy, name)
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
			report.Executables = append(report.Executables, p)
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
	slices.Sort(report.Executables)
	slices.Sort(report.Stale)
	slices.Sort(report.Libraries)
	slices.Sort(report.Unknown)

	// s.Executables is sorted, so NotAllowed is sorted too.
	for _, p := range s.Executables {
		if !allowed[p] {
			report.NotAllowed = append(report.NotAllowed, p)
		}
	}
	report.Allowed = slices.Sorted(maps.Keys(allowed))
	return report
}

// printPaths prints a heading followed by the paths, one per line.
func printPaths(w io.Writer, heading string, paths []string) {
	fmt.Fprintf(w, "    %s:\n", heading)
	for _, p := range paths {
		fmt.Fprintf(w, "      %s\n", p)
	}
}

func renderCheckText(w io.Writer, result *checkResult, listNotAllowed bool) {
	namespace := result.Policy.Namespace
	if namespace == "" {
		namespace = "<none>"
	}
	fmt.Fprintf(w, "Policy %q (namespace %s):\n", result.Policy.Name, namespace)

	for _, r := range result.Containers {
		renderContainerText(w, r, listNotAllowed)
	}
}

func renderContainerText(w io.Writer, r containerReport, listNotAllowed bool) {
	label := fmt.Sprintf("container %q", r.Name)
	if r.Init {
		label = "init " + label
	}
	fmt.Fprintf(w, "  %s (image %s):\n", label, r.Image)

	if len(r.Executables) == len(r.Allowed) {
		fmt.Fprintf(w, "    all %d allowed paths are executables in the image\n", len(r.Allowed))
	} else {
		fmt.Fprintf(w, "    %d of %d allowed paths are executables in the image\n",
			len(r.Executables), len(r.Allowed))
	}

	if len(r.Stale) > 0 {
		stale := make([]string, 0, len(r.Stale))
		for _, p := range r.Stale {
			if target, isLink := r.Links[p]; isLink {
				p = fmt.Sprintf("%s (symbolic link to %s, the enforcer reports %s)", p, target, target)
			}
			stale = append(stale, p)
		}
		printPaths(w, fmt.Sprintf("%d allowed paths are not executables in the image", len(r.Stale)), stale)
	}
	if len(r.Libraries) > 0 {
		printPaths(w, fmt.Sprintf("%d allowed paths are shared libraries, which wpgen skips unless --%s is set",
			len(r.Libraries), includeLibrariesFlag), r.Libraries)
	}
	if len(r.Unknown) > 0 {
		printPaths(
			w,
			fmt.Sprintf("%d allowed paths are neither programs nor scripts, which wpgen skips unless --%s is set",
				len(r.Unknown), includeUnknownFlag),
			r.Unknown,
		)
	}

	heading := fmt.Sprintf("%d executables of the image are not allowed", len(r.NotAllowed))
	if listNotAllowed && len(r.NotAllowed) > 0 {
		printPaths(w, heading, r.NotAllowed)
	} else {
		fmt.Fprintf(w, "    %s\n", heading)
	}
}

type jsonPolicy struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type jsonStalePath struct {
	Path string `json:"path"`
	// LinkTarget is the real path, when the path is a symbolic link.
	LinkTarget string `json:"linkTarget,omitempty"`
}

type jsonSkippedPath struct {
	Path string         `json:"path"`
	Kind imagescan.Kind `json:"kind"`
}

type jsonContainer struct {
	Name            string            `json:"name"`
	Init            bool              `json:"init"`
	Image           string            `json:"image"`
	Allowed         []string          `json:"allowed"`
	Executables     []string          `json:"executables"`
	Stale           []jsonStalePath   `json:"stale"`
	Skipped         []jsonSkippedPath `json:"skipped"`
	NotAllowedCount int               `json:"notAllowedCount"`
	NotAllowed      []string          `json:"notAllowed,omitzero"`
}

type jsonCheckResult struct {
	Policy                   jsonPolicy      `json:"policy"`
	Containers               []jsonContainer `json:"containers"`
	ContainersOnlyInPolicy   []string        `json:"containersOnlyInPolicy"`
	ContainersOnlyInWorkload []string        `json:"containersOnlyInWorkload"`
}

// nonNil returns an empty slice instead of nil, so that JSON has [] and not
// null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func renderCheckJSON(w io.Writer, result *checkResult, listNotAllowed bool) error {
	out := jsonCheckResult{
		Policy:                   jsonPolicy{Name: result.Policy.Name, Namespace: result.Policy.Namespace},
		Containers:               make([]jsonContainer, 0, len(result.Containers)),
		ContainersOnlyInPolicy:   nonNil(result.OnlyInPolicy),
		ContainersOnlyInWorkload: nonNil(result.OnlyInWorkload),
	}

	for _, r := range result.Containers {
		c := jsonContainer{
			Name:            r.Name,
			Init:            r.Init,
			Image:           r.Image,
			Allowed:         nonNil(r.Allowed),
			Executables:     nonNil(r.Executables),
			Stale:           []jsonStalePath{},
			Skipped:         []jsonSkippedPath{},
			NotAllowedCount: len(r.NotAllowed),
		}
		for _, p := range r.Stale {
			c.Stale = append(c.Stale, jsonStalePath{Path: p, LinkTarget: r.Links[p]})
		}
		for _, p := range r.Libraries {
			c.Skipped = append(c.Skipped, jsonSkippedPath{Path: p, Kind: imagescan.KindLibrary})
		}
		for _, p := range r.Unknown {
			c.Skipped = append(c.Skipped, jsonSkippedPath{Path: p, Kind: imagescan.KindUnknown})
		}
		slices.SortFunc(c.Skipped, func(a, b jsonSkippedPath) int { return strings.Compare(a.Path, b.Path) })
		if listNotAllowed {
			c.NotAllowed = nonNil(r.NotAllowed)
		}
		out.Containers = append(out.Containers, c)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		return fmt.Errorf("cannot write the JSON report: %w", err)
	}
	return nil
}
