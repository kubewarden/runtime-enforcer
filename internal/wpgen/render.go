package wpgen

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
)

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
// reported, when an allowed path is stale, or when a container of the
// workload has no rules in the policy: the enforcer does not protect such a
// container. Then it adds a note for each thing that the check did not cover.
func printVerdict(w io.Writer, p painter, result *checkResult) error {
	var problems []string

	if stale := result.stale(); stale > 0 {
		msg := count(stale, "allowed path is not an executable in the images",
			"allowed paths are not executables in the images")
		fmt.Fprintf(w, "\n%s\n", p.failure(msg+":"))
		for _, r := range result.Containers {
			if len(r.Stale) > 0 {
				fmt.Fprintf(w, "  %s: %s\n", containerLabel(r.Name, r.Init), strings.Join(r.Stale, ", "))
			}
		}
		problems = append(problems, msg)
	}

	if n := len(result.OnlyInWorkload); n > 0 {
		msg := count(n, "container of the workload has no rules in the policy",
			"containers of the workload have no rules in the policy")
		pronoun := "it"
		if n > 1 {
			pronoun = "them"
		}
		fmt.Fprintf(w, "\n%s\n", p.failure(fmt.Sprintf("%s, so the enforcer does not protect %s:", msg, pronoun)))
		fmt.Fprintf(w, "  %s\n", strings.Join(result.OnlyInWorkload, ", "))
		problems = append(problems, msg)
	}

	if len(problems) == 0 {
		fmt.Fprintf(w, "\n%s\n", p.success("No allowed path is stale."))
	}

	var notes []string
	if skipped := result.skipped(); skipped > 0 {
		notes = append(notes, count(skipped,
			"allowed path was skipped: it is a shared library, or a file that is neither a program nor a script.",
			"allowed paths were skipped: they are shared libraries, or files that are neither programs nor scripts."))
	}
	if n := len(result.OnlyInPolicy); n > 0 {
		notes = append(notes, count(n,
			"container of the policy was not checked: it is not in "+result.Workload+".",
			"containers of the policy were not checked: they are not in "+result.Workload+"."))
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
		for _, note := range notes {
			fmt.Fprintln(w, p.notice(note))
		}
	}

	if len(problems) > 0 {
		return &reportedError{msg: strings.Join(problems, ", and ")}
	}
	return nil
}

// count returns n followed by the singular or the plural text.
func count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
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
	var skipped []checkRow
	for _, p := range r.Libraries {
		skipped = append(skipped, checkRow{
			Path: p, Status: statusSkipped, Note: "shared library, see --" + includeLibrariesFlag,
		})
	}
	for _, p := range r.Unknown {
		skipped = append(skipped, checkRow{
			Path: p, Status: statusSkipped, Note: "neither a program nor a script, see --" + includeUnknownFlag,
		})
	}
	slices.SortFunc(skipped, func(a, b checkRow) int { return strings.Compare(a.Path, b.Path) })
	rows = append(rows, skipped...)
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

// renderCheckTable writes the table report. It returns the first write error:
// the report is the data of the command, and a lost report is a failure.
func renderCheckTable(out io.Writer, p painter, result *checkResult, listNotAllowed bool) error {
	w := &stickyWriter{w: out}

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

	if w.err != nil {
		return fmt.Errorf("cannot write the table report: %w", w.err)
	}
	return nil
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
