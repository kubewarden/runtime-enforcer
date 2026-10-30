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

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
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
	// Workload describes the workload, for example `Deployment "web"`. It is
	// empty with --image.
	Workload string
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

The report goes to standard output, as a table or as JSON. Other messages go
to standard error.`,
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
		if err = renderCheckJSON(s.out, result, opts.ListNotAllowed); err != nil {
			return err
		}
	} else {
		renderCheckTable(s.out, s.outPainter, result, opts.ListNotAllowed)
	}

	return printVerdict(s.err, s.errPainter, result)
}

// printMismatches prints a notice for each container that is only in the
// policy or only in the workload.
func printMismatches(w io.Writer, p painter, result *checkResult) {
	if len(result.OnlyInWorkload)+len(result.OnlyInPolicy) == 0 {
		return
	}
	defer fmt.Fprintln(w)
	for _, name := range result.OnlyInWorkload {
		fmt.Fprintln(w, p.notice(fmt.Sprintf("The policy has no rules for container %q of %s.", name, result.Workload)))
	}
	for _, name := range result.OnlyInPolicy {
		fmt.Fprintln(w, p.notice(fmt.Sprintf("The policy has rules for container %q, which is not in %s.",
			name, result.Workload)))
	}
}

// printVerdict prints the result of the check. It returns an error, already
// reported, when an allowed path is not an executable in the image.
func printVerdict(w io.Writer, p painter, result *checkResult) error {
	stale := result.stale()
	if stale == 0 {
		fmt.Fprintf(w, "\n%s\n", p.success("All allowed paths are executables in the images."))
		return nil
	}

	msg := fmt.Sprintf("%d allowed paths are not executables in the images", stale)
	if stale == 1 {
		msg = "1 allowed path is not an executable in the images"
	}
	fmt.Fprintf(w, "\n%s\n", p.failure(msg+":"))
	for _, r := range result.Containers {
		if len(r.Stale) > 0 {
			fmt.Fprintf(w, "  %s: %s\n", containerLabel(r.Name, r.Init), strings.Join(r.Stale, ", "))
		}
	}
	return &reportedError{msg: msg}
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

// matchContainers returns the containers of the workload that the policy has
// rules for. It records the workload, and the containers that are only in
// the policy or only in the workload, in the result.
func matchContainers(result *checkResult, workload workloadparse.Workload) ([]checkedContainer, error) {
	policy := result.Policy
	result.Workload = fmt.Sprintf("%s %q", workload.Kind, workload.Name)

	var containers []checkedContainer
	inWorkload := map[string]bool{}
	for _, c := range workload.Containers {
		inWorkload[c.Name] = true
		rules, found := policy.Spec.RulesByContainer[c.Name]
		if !found {
			result.OnlyInWorkload = append(result.OnlyInWorkload, c.Name)
			continue
		}
		containers = append(containers, checkedContainer{Container: c, Allowed: allowedPaths(rules)})
	}

	for _, name := range slices.Sorted(maps.Keys(policy.Spec.RulesByContainer)) {
		if !inWorkload[name] {
			result.OnlyInPolicy = append(result.OnlyInPolicy, name)
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

const (
	statusStale      = "stale"
	statusSkipped    = "skipped"
	statusOK         = "ok"
	statusNotAllowed = "not allowed"

	noteMaxWidth = 50
	// halves divides the rows of a container to find the middle one.
	halves = 2
)

// checkRow is one path of a container in the table report.
type checkRow struct {
	Path   string
	Status string
	Note   string
}

// containerRows returns the rows of a container, sorted by status: the paths
// that need an action first. The paths of each status are sorted.
func containerRows(r containerReport, listNotAllowed bool) []checkRow {
	var rows []checkRow
	for _, p := range r.Stale {
		note := "not an executable in the image"
		if target, isLink := r.Links[p]; isLink {
			note = fmt.Sprintf("symbolic link to %s, the enforcer reports the target", target)
		}
		rows = append(rows, checkRow{Path: p, Status: statusStale, Note: note})
	}
	for _, p := range r.Libraries {
		rows = append(rows, checkRow{
			Path: p, Status: statusSkipped, Note: "shared library, see --" + includeLibrariesFlag,
		})
	}
	for _, p := range r.Unknown {
		rows = append(rows, checkRow{
			Path: p, Status: statusSkipped, Note: "neither a program nor a script, see --" + includeUnknownFlag,
		})
	}
	for _, p := range r.Executables {
		rows = append(rows, checkRow{Path: p, Status: statusOK})
	}
	if listNotAllowed {
		for _, p := range r.NotAllowed {
			rows = append(rows, checkRow{Path: p, Status: statusNotAllowed})
		}
	}
	return rows
}

func renderCheckTable(w io.Writer, p painter, result *checkResult, listNotAllowed bool) {
	namespace := result.Policy.Namespace
	if namespace == "" {
		namespace = "<none>"
	}
	fmt.Fprintf(w, "Policy %s (namespace %s)\n\n", result.Policy.Name, namespace)

	const note = "Note"
	paths := newTable(table.Row{headerContainer, "Path", "Status", note},
		table.ColumnConfig{Name: headerContainer, Align: text.AlignCenter, AlignHeader: text.AlignCenter},
		table.ColumnConfig{Name: note, WidthMax: noteMaxWidth, WidthMaxEnforcer: text.WrapSoft},
	)
	for i, r := range result.Containers {
		if i > 0 {
			paths.AppendSeparator()
		}
		rows := containerRows(r, listNotAllowed)
		if len(rows) == 0 {
			rows = []checkRow{{Note: "the policy allows no paths"}}
		}
		// The name goes in the middle row of the container, so that it
		// looks centered across all its rows.
		middle := (len(rows) - 1) / halves
		for j, row := range rows {
			var label string
			if j == middle {
				label = p.strong(containerLabel(r.Name, r.Init))
			}
			paths.AppendRow(table.Row{label, row.Path, row.Status, row.Note})
		}
	}
	renderTable(w, paths)
	fmt.Fprintln(w)

	counts := []string{"Allowed", "OK", "Stale", "Skipped", "Not allowed"}
	header := table.Row{headerContainer, "Image"}
	for _, c := range counts {
		header = append(header, c)
	}
	summary := newTable(header, alignRight(counts...)...)
	for _, r := range result.Containers {
		summary.AppendRow(table.Row{
			containerLabel(r.Name, r.Init),
			r.Image,
			len(r.Allowed),
			len(r.Executables),
			len(r.Stale),
			len(r.Libraries) + len(r.Unknown),
			len(r.NotAllowed),
		})
	}
	renderTable(w, summary)
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
