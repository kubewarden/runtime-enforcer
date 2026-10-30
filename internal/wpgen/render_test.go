package wpgen

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/imagescan"
)

// snapshotResult is a check of a policy against the scan fixture of a real
// image: a container with stale paths and a skipped library, and an init
// container where all the allowed paths are executables.
func snapshotResult(t *testing.T) *checkResult {
	t.Helper()

	snapshot := loadSnapshot(t, golangSnapshot)
	main := checkedContainer{
		Name:  "main",
		Image: snapshot.Image,
		Allowed: []string{
			"/usr/local/go/bin/go",
			"/usr/local/go/bin/gofmt",
			"/bin/sh",
			"/lib/libz.so.1.2.11",
			"/usr/local/bin/wait-for-it.sh",
		},
	}
	setup := checkedContainer{
		Name:    "setup",
		Image:   snapshot.Image,
		Init:    true,
		Allowed: []string{"/bin/busybox"},
	}

	result := &checkResult{
		Policy: &v1alpha1.WorkloadPolicy{Name: "deploy-web", Namespace: "prod"},
	}
	for _, c := range []checkedContainer{main, setup} {
		result.Containers = append(result.Containers,
			compare(c, scannedFromSnapshot(t, snapshot, scanOptions{}, c.Allowed)))
	}
	return result
}

// tinyResult is a check with a short list of executables that the policy
// does not allow, and containers that are only in one side.
func tinyResult() *checkResult {
	return &checkResult{
		Policy:         &v1alpha1.WorkloadPolicy{Name: "api"},
		Workload:       `Deployment "api"`,
		OnlyInPolicy:   []string{"removed"},
		OnlyInWorkload: []string{"sidecar"},
		Containers: []containerReport{
			compare(checked("/bin/busybox", "/etc/ca.crt"), tinyImage()),
		},
	}
}

func TestRenderCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		result         func(t *testing.T) *checkResult
		format         string
		listNotAllowed bool
	}{
		{name: "check-table", result: snapshotResult, format: outputTable},
		{name: "check-json", result: snapshotResult, format: outputJSON},
		{
			name:           "check-table-not-allowed",
			result:         func(*testing.T) *checkResult { return tinyResult() },
			format:         outputTable,
			listNotAllowed: true,
		},
		{
			name:           "check-json-not-allowed",
			result:         func(*testing.T) *checkResult { return tinyResult() },
			format:         outputJSON,
			listNotAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			if tt.format == outputJSON {
				require.NoError(t, renderCheckJSON(&out, tt.result(t), tt.listNotAllowed))
			} else {
				require.NoError(t, renderCheckTable(&out, painter{}, tt.result(t), tt.listNotAllowed))
			}
			assertGolden(t, tt.name, out.String())
		})
	}
}

func TestPrintVerdict(t *testing.T) {
	t.Parallel()

	clean := tinyResult()
	clean.Containers = []containerReport{compare(checked("/bin/busybox"), tinyImage())}

	tests := []struct {
		name   string
		result *checkResult
		err    string
	}{
		{name: "verdict-stale", result: snapshotResult(t), err: "2 allowed paths are not executables in the images"},
		{name: "verdict-clean", result: clean},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			err := printVerdict(&out, painter{}, tt.result)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				require.True(t, isReported(err), "the verdict already shows the error")
			} else {
				require.NoError(t, err)
			}
			assertGolden(t, tt.name, out.String())
		})
	}
}

func TestPrintMismatches(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	printMismatches(&out, painter{}, tinyResult())
	assertGolden(t, "mismatches", out.String())

	out.Reset()
	printMismatches(&out, painter{}, &checkResult{})
	require.Empty(t, out.String(), "no notices and no blank line when the containers match")
}

func TestRenderCheckJSONEmptyLists(t *testing.T) {
	t.Parallel()

	result := tinyResult()
	result.OnlyInPolicy, result.OnlyInWorkload = nil, nil
	result.Containers = []containerReport{
		compare(checked("/bin/busybox", "/bin/tool", "/entrypoint.sh"), tinyImage()),
	}

	var out bytes.Buffer
	require.NoError(t, renderCheckJSON(&out, result, true))
	require.Contains(t, out.String(), `"notAllowed": []`, "an empty list is present with --list-not-allowed")
	require.Contains(t, out.String(), `"containersOnlyInPolicy": []`)
	require.NotContains(t, out.String(), "null")
}

func TestPrintDraftSummary(t *testing.T) {
	t.Parallel()

	snapshot := loadSnapshot(t, golangSnapshot)
	tests := []struct {
		name string
		opts scanOptions
	}{
		{name: "draft-summary"},
		{name: "draft-summary-include", opts: scanOptions{IncludeLibraries: true, IncludeUnknown: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scanned := scannedFromSnapshot(t, snapshot, tt.opts, nil)
			small := &scannedImage{Executables: []string{"/bin/app"}, Skipped: map[string]imagescan.Kind{}}

			var out bytes.Buffer
			printDraftSummary(&out, painter{}, []draftedContainer{
				{Label: "main", Image: snapshot.Image, Scanned: scanned},
				{Label: containerLabel("setup", true), Image: "setup:1", Scanned: small},
			}, defaultWarnThreshold)
			assertGolden(t, tt.name, out.String())
		})
	}
}

func TestRenderCheckTableWriteError(t *testing.T) {
	t.Parallel()

	err := renderCheckTable(&failingWriter{}, painter{}, tinyResult(), false)
	require.ErrorIs(t, err, errNoSpace)
	require.ErrorContains(t, err, "cannot write the table report")
}
