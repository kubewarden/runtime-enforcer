package wpgen

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	"github.com/kubewarden/runtime-enforcer/internal/workloadparse"
)

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
	workloadMatch

	Policy     *v1alpha1.WorkloadPolicy
	Containers []containerReport
}

// workloadMatch is the result of the match of the containers of the policy
// with the containers of the workload. It is empty with --image.
type workloadMatch struct {
	// Workload describes the workload, for example `Deployment "web"`.
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

// skipped returns the number of skipped paths of all the containers.
func (r *checkResult) skipped() int {
	n := 0
	for _, c := range r.Containers {
		n += len(c.Libraries) + len(c.Unknown)
	}
	return n
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

// matchContainers returns the containers of the workload that the policy has
// rules for, and the match of the containers of both.
func matchContainers(
	policy *v1alpha1.WorkloadPolicy,
	workload workloadparse.Workload,
) ([]checkedContainer, workloadMatch, error) {
	match := workloadMatch{Workload: fmt.Sprintf("%s %q", workload.Kind, workload.Name)}

	var containers []checkedContainer
	inWorkload := map[string]bool{}
	for _, c := range workload.Containers {
		inWorkload[c.Name] = true
		rules, found := policy.Spec.RulesByContainer[c.Name]
		if !found {
			match.OnlyInWorkload = append(match.OnlyInWorkload, c.Name)
			continue
		}
		containers = append(containers, checkedContainer{Container: c, Allowed: allowedPaths(rules)})
	}

	for _, name := range slices.Sorted(maps.Keys(policy.Spec.RulesByContainer)) {
		if !inWorkload[name] {
			match.OnlyInPolicy = append(match.OnlyInPolicy, name)
		}
	}

	if len(containers) == 0 {
		return nil, workloadMatch{}, fmt.Errorf("the policy and %s %q have no container in common",
			workload.Kind, workload.Name)
	}
	return containers, match, nil
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
