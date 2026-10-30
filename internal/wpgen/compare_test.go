package wpgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
	"github.com/kubewarden/runtime-enforcer/internal/workloadparse"
)

// tinyImage is a scanned image with one executable of each kind.
func tinyImage() *scannedImage {
	return &scannedImage{
		Executables: []string{"/bin/busybox", "/bin/tool", "/entrypoint.sh"},
		Skipped: map[string]imagescan.Kind{
			"/lib/libz.so.1": imagescan.KindLibrary,
			"/etc/ca.crt":    imagescan.KindUnknown,
		},
		Links: map[string]string{"/bin/sh": "/bin/busybox"},
	}
}

// checked returns the container "main" of image "tiny:1", with the allowed paths.
func checked(allowed ...string) checkedContainer {
	return checkedContainer{Name: "main", Image: "tiny:1", Allowed: allowed}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		allowed  []string
		expected containerReport
	}{
		{
			name:    "all allowed paths are executables",
			allowed: []string{"/bin/busybox", "/entrypoint.sh"},
			expected: containerReport{
				Executables: []string{"/bin/busybox", "/entrypoint.sh"},
				NotAllowed:  []string{"/bin/tool"},
			},
		},
		{
			name:    "missing path and symbolic link are stale",
			allowed: []string{"/bin/busybox", "/bin/sh", "/usr/bin/gone"},
			expected: containerReport{
				Executables: []string{"/bin/busybox"},
				Stale:       []string{"/bin/sh", "/usr/bin/gone"},
				Links:       map[string]string{"/bin/sh": "/bin/busybox"},
				NotAllowed:  []string{"/bin/tool", "/entrypoint.sh"},
			},
		},
		{
			name:    "skipped kinds are not stale",
			allowed: []string{"/lib/libz.so.1", "/etc/ca.crt"},
			expected: containerReport{
				Libraries:  []string{"/lib/libz.so.1"},
				Unknown:    []string{"/etc/ca.crt"},
				NotAllowed: []string{"/bin/busybox", "/bin/tool", "/entrypoint.sh"},
			},
		},
		{
			name:    "duplicate allowed paths count once",
			allowed: []string{"/bin/tool", "/bin/tool", "/usr/bin/gone", "/usr/bin/gone"},
			expected: containerReport{
				Executables: []string{"/bin/tool"},
				Stale:       []string{"/usr/bin/gone"},
				NotAllowed:  []string{"/bin/busybox", "/entrypoint.sh"},
			},
		},
		{
			name:    "no allowed paths",
			allowed: nil,
			expected: containerReport{
				NotAllowed: []string{"/bin/busybox", "/bin/tool", "/entrypoint.sh"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := compare(checked(tt.allowed...), tinyImage())
			assert.Equal(t, tt.expected.Executables, got.Executables)
			assert.Equal(t, tt.expected.Stale, got.Stale)
			assert.Equal(t, tt.expected.Libraries, got.Libraries)
			assert.Equal(t, tt.expected.Unknown, got.Unknown)
			assert.Equal(t, tt.expected.NotAllowed, got.NotAllowed)
			if tt.expected.Links == nil {
				assert.Empty(t, got.Links)
			} else {
				assert.Equal(t, tt.expected.Links, got.Links)
			}
		})
	}
}

// TestCompareSnapshot runs the comparison on the scan fixture of a real
// image, with each combination of the flags that change the kinds.
func TestCompareSnapshot(t *testing.T) {
	t.Parallel()

	snapshot := loadSnapshot(t, golangSnapshot)
	allowed := []string{
		"/usr/local/go/bin/go",
		"/bin/sh",
		"/lib/libz.so.1.2.11",
		"/usr/bin/gone",
	}

	tests := []struct {
		name        string
		opts        scanOptions
		executables []string
		stale       []string
		libraries   []string
		notAllowed  int
	}{
		{
			name:        "default",
			executables: []string{"/usr/local/go/bin/go"},
			stale:       []string{"/bin/sh", "/usr/bin/gone"},
			libraries:   []string{"/lib/libz.so.1.2.11"},
			notAllowed:  96,
		},
		{
			name:        "include libraries",
			opts:        scanOptions{IncludeLibraries: true},
			executables: []string{"/lib/libz.so.1.2.11", "/usr/local/go/bin/go"},
			stale:       []string{"/bin/sh", "/usr/bin/gone"},
			notAllowed:  103,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report := compare(checked(allowed...), scannedFromSnapshot(t, snapshot, tt.opts, allowed))
			assert.Equal(t, tt.executables, report.Executables)
			assert.Equal(t, tt.stale, report.Stale)
			assert.Equal(t, tt.libraries, report.Libraries)
			assert.Equal(t, map[string]string{"/bin/sh": "/bin/busybox"}, report.Links)
			assert.Len(t, report.NotAllowed, tt.notAllowed)
		})
	}
}

func TestContainerRows(t *testing.T) {
	t.Parallel()

	report := compare(
		checked("/usr/bin/gone", "/bin/busybox", "/etc/ca.crt", "/bin/sh", "/lib/libz.so.1"),
		tinyImage(),
	)

	assert.Equal(t, []checkRow{
		{Path: "/bin/sh", Status: statusStale, Note: "symbolic link to /bin/busybox, the enforcer reports the target"},
		{Path: "/usr/bin/gone", Status: statusStale, Note: "not an executable in the image"},
		{Path: "/etc/ca.crt", Status: statusSkipped, Note: "neither a program nor a script, see --include-unknown"},
		{Path: "/lib/libz.so.1", Status: statusSkipped, Note: "shared library, see --include-libraries"},
		{Path: "/bin/busybox", Status: statusOK},
	}, containerRows(report, false), "the skipped paths of both kinds are sorted together")

	withNotAllowed := containerRows(report, true)
	assert.Equal(t, []checkRow{
		{Path: "/bin/tool", Status: statusNotAllowed},
		{Path: "/entrypoint.sh", Status: statusNotAllowed},
	}, withNotAllowed[len(withNotAllowed)-2:], "the paths that the policy does not allow come last")
}

func TestMatchContainers(t *testing.T) {
	t.Parallel()

	policy := &v1alpha1.WorkloadPolicy{Spec: v1alpha1.WorkloadPolicySpec{
		RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
			"web":     {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/web"}}},
			"setup":   nil,
			"removed": {},
		},
	}}
	workload := workloadparse.Workload{
		Kind: workloadkind.Deployment,
		Name: "web",
		Containers: []workloadparse.Container{
			{Name: "web", Image: "web:1"},
			{Name: "sidecar", Image: "proxy:1"},
			{Name: "setup", Image: "setup:1", Init: true},
		},
	}

	result := &checkResult{Policy: policy}
	containers, err := matchContainers(result, workload)
	require.NoError(t, err)

	assert.Equal(t, []checkedContainer{
		{Name: "web", Image: "web:1", Allowed: []string{"/bin/web"}},
		{Name: "setup", Image: "setup:1", Init: true},
	}, containers)
	assert.Equal(t, `Deployment "web"`, result.Workload)
	assert.Equal(t, []string{"removed"}, result.OnlyInPolicy)
	assert.Equal(t, []string{"sidecar"}, result.OnlyInWorkload)

	_, err = matchContainers(&checkResult{Policy: policy}, workloadparse.Workload{
		Kind:       workloadkind.Job,
		Name:       "other",
		Containers: []workloadparse.Container{{Name: "other", Image: "other:1"}},
	})
	require.EqualError(t, err, `the policy and Job "other" have no container in common`)
}

func TestImageContainers(t *testing.T) {
	t.Parallel()

	rules := func(paths ...string) *v1alpha1.WorkloadPolicyRules {
		return &v1alpha1.WorkloadPolicyRules{Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: paths}}
	}
	single := &v1alpha1.WorkloadPolicy{Spec: v1alpha1.WorkloadPolicySpec{
		RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{"main": rules("/bin/app")},
	}}
	several := &v1alpha1.WorkloadPolicy{Spec: v1alpha1.WorkloadPolicySpec{
		RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
			"main":    rules("/bin/app"),
			"sidecar": rules("/bin/proxy"),
		},
	}}

	tests := []struct {
		name          string
		policy        *v1alpha1.WorkloadPolicy
		containerName string
		expected      string
		err           string
	}{
		{name: "the only container", policy: single, expected: "main"},
		{name: "a named container", policy: several, containerName: "sidecar", expected: "sidecar"},
		{
			name:   "a name is needed",
			policy: several,
			err:    "the policy has 2 containers, use --container-name to choose one",
		},
		{name: "an unknown name", policy: several, containerName: "nope", err: `the policy has no container "nope"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			containers, err := imageContainers(tt.policy, "img:1", tt.containerName)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Len(t, containers, 1)
			assert.Equal(t, tt.expected, containers[0].Name)
			assert.Equal(t, "img:1", containers[0].Image)
			assert.Equal(t, tt.policy.Spec.RulesByContainer[tt.expected].Executables.Allowed, containers[0].Allowed)
		})
	}
}
