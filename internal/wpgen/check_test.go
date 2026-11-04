package wpgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
	wpt "github.com/kubewarden/runtime-enforcer/internal/workloadparse/workloadparsetest"
)

// The tests in this file run the check command end to end, to test the
// wiring: flags, input files, exit code and output streams. The comparison
// rules are tested in compare_test.go, and the layout in render_test.go.

// busyboxImage has two executables, and symbolic links to one of them.
func busyboxImage(t *testing.T) string {
	t.Helper()

	return ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"),
		ist.Reg("usr/bin/busybox", 0o755),
		ist.Reg("usr/bin/extra", 0o755),
		ist.Symlink("usr/bin/sh", "busybox"),
		ist.Symlink("bin", "usr/bin"),
	))
}

func newPolicy(t *testing.T, executablesByContainer map[string][]string) *v1alpha1.WorkloadPolicy {
	t.Helper()

	policy, err := policydraft.New("deploy-web", "prod", "monitor", executablesByContainer)
	require.NoError(t, err)
	return policy
}

// policyYAML returns the YAML of the policies, as writePolicies writes it.
func policyYAML(t *testing.T, policies ...*v1alpha1.WorkloadPolicy) string {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, policydraft.EncodeAll(&buf, policies, policydraft.FormatYAML))
	return buf.String()
}

func writePolicies(t *testing.T, policies ...*v1alpha1.WorkloadPolicy) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policyYAML(t, policies...)), 0o600))
	return path
}

func deploymentWith(containers ...corev1.Container) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: objectMeta("web", "prod"), Spec: appsv1.DeploymentSpec{
		Template: podTemplate(nil, containers...),
	}}
}

func TestCheckCmdWorkload(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	workload := deploymentWith(
		corev1.Container{Name: "shell", Image: img},
		corev1.Container{Name: "tools", Image: img},
		corev1.Container{Name: "unknown", Image: img},
	)
	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"shell": {"/usr/bin/busybox", "/usr/local/bin/gone"},
		"tools": {"/usr/bin/busybox"},
	}))

	stdout, stderr, err := runWpgen(t, "check", policy,
		"--workload", wpt.WriteFile(t, workload), "--image-src", "oci-dir")

	require.EqualError(t, err, "1 allowed path is not an executable in the images, "+
		"and 1 container of the workload has no rules in the policy")
	assert.True(t, strings.HasPrefix(stdout, "Policy deploy-web (namespace prod)\n"), "the report goes to stdout")
	assert.Contains(t, stdout, "/usr/local/bin/gone")
	assert.Equal(t, 1, strings.Count(stderr, fmt.Sprintf("Loading image %q", img)), "each image is scanned once")
	assert.Contains(t, stderr, `The policy has no rules for container "unknown" of Deployment "web".`)
	assert.Equal(t, 1, strings.Count(stderr, "1 allowed path is not an executable in the images"),
		"the verdict is printed once")
	assert.Contains(t, stderr, "1 container of the workload has no rules in the policy, "+
		"so the enforcer does not protect it:\n  unknown\n")
}

// TestCheckCmdNewContainer checks a policy made for two containers against a
// workload with a third, new container. Nothing is stale, but the enforcer
// does not protect the new container, so the check fails.
func TestCheckCmdNewContainer(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	workload := deploymentWith(
		corev1.Container{Name: "shell", Image: img},
		corev1.Container{Name: "tools", Image: img},
		corev1.Container{Name: "sidecar", Image: img},
	)
	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"shell": {"/usr/bin/busybox"},
		"tools": {"/usr/bin/extra"},
	}))

	_, stderr, err := runWpgen(t, "check", policy,
		"--workload", wpt.WriteFile(t, workload), "--image-src", "oci-dir")

	require.EqualError(t, err, "1 container of the workload has no rules in the policy")
	assert.Contains(t, stderr, "so the enforcer does not protect it:\n  sidecar\n")
	assert.NotContains(t, stderr, "No allowed path is stale")
}

func TestCheckCmdImage(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"main":    {"/usr/bin/busybox"},
		"sidecar": {"/usr/bin/extra"},
	}))

	stdout, stderr, err := runWpgen(t, "check", policy, "--image", img, "--container-name", "sidecar",
		"--image-src", "oci-dir")
	require.NoError(t, err)
	assert.Contains(t, stdout, "sidecar")
	assert.NotContains(t, stdout, "/usr/bin/busybox", "only the chosen container is checked")
	assert.Contains(t, stderr, "No allowed path is stale.")
}

// TestCheckCmdReportWriteError checks that a report that cannot be written
// fails the command, even when the policy matches the image.
func TestCheckCmdReportWriteError(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	policy := writePolicies(t, newPolicy(t, map[string][]string{"main": {"/usr/bin/busybox"}}))

	for _, format := range []string{outputTable, outputJSON} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()

			var stderr bytes.Buffer
			cmd := newRootCmd(testGlobalOptions())
			cmd.SetArgs([]string{"check", policy, "--image", img, "--image-src", "oci-dir", "-o", format})
			cmd.SetOut(&failingWriter{})
			cmd.SetErr(&stderr)

			err := cmd.ExecuteContext(t.Context())
			require.ErrorIs(t, err, errNoSpace)
			assert.NotContains(t, stderr.String(), "No allowed path is stale",
				"no verdict when the report is lost")
		})
	}
}

func TestCheckCmdJSON(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	policy := writePolicies(t, newPolicy(t, map[string][]string{"main": {"/usr/bin/busybox", "/bin/sh"}}))

	stdout, _, err := runWpgen(t, "check", policy, "--image", img, "--image-src", "oci-dir",
		"-o", "json", "--list-not-allowed")
	require.EqualError(t, err, "1 allowed path is not an executable in the images")

	var got jsonCheckResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &got), "standard output is one JSON document")
	require.Len(t, got.Containers, 1)
	assert.Equal(t, []jsonStalePath{{Path: "/bin/sh", LinkTarget: "/usr/bin/busybox"}}, got.Containers[0].Stale)
	assert.Equal(t, []string{"/usr/bin/extra"}, got.Containers[0].NotAllowed, "--list-not-allowed is applied")
}

func TestCheckCmdProposalFromStdin(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	proposal := &v1alpha1.WorkloadPolicyProposal{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "WorkloadPolicyProposal",
		Name:       "deploy-web",
		Spec: v1alpha1.WorkloadPolicyProposalSpec{RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
			"shell": {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/usr/bin/busybox"}}},
		}},
	}
	data, err := yaml.Marshal(proposal)
	require.NoError(t, err)

	stdout, _, err := runWpgenWithStdin(t, bytes.NewReader(data), "check", "-",
		"--workload", wpt.WriteFile(t, deploymentWith(corev1.Container{Name: "shell", Image: img})),
		"--image-src", "oci-dir")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(stdout, "Policy deploy-web (namespace <none>)\n"))
}

func TestCheckCmdErrors(t *testing.T) {
	t.Parallel()

	policy := newPolicy(t, map[string][]string{"web": {"/usr/bin/web"}})
	deployment := func(name string) runtime.Object {
		return &appsv1.Deployment{ObjectMeta: objectMeta(name, ""), Spec: appsv1.DeploymentSpec{
			Template: podTemplate(nil, corev1.Container{Name: "web", Image: "web:1"}),
		}}
	}

	tests := []struct {
		name string
		args func(t *testing.T) []string
		err  string
	}{
		{
			name: "neither --workload nor --image",
			args: func(t *testing.T) []string {
				return []string{writePolicies(t, policy)}
			},
			err: "at least one of the flags in the group [workload image] is required",
		},
		{
			name: "both --workload and --image",
			args: func(t *testing.T) []string {
				return []string{writePolicies(t, policy), "--workload", "w.yaml", "--image", "web:1"}
			},
			err: "if any flags in the group [workload image] are set none of the others can be",
		},
		{
			name: "--container-name without --image",
			args: func(t *testing.T) []string {
				return []string{writePolicies(t, policy), "--workload", "w.yaml", "--container-name", "web"}
			},
			err: "--container-name needs --image",
		},
		{
			name: "policy and workload from standard input",
			args: func(_ *testing.T) []string {
				return []string{"-", "--workload", "-"}
			},
			err: "the policy and the workload cannot both come from standard input",
		},
		{
			name: "invalid output format",
			args: func(t *testing.T) []string {
				return []string{writePolicies(t, policy), "--image", "web:1", "-o", "yaml"}
			},
			err: `invalid output format "yaml": must be "table" or "json"`,
		},
		{
			name: "no policy in the file",
			args: func(t *testing.T) []string {
				return []string{wpt.WriteFile(t, deployment("web")), "--image", "web:1"}
			},
			err: "must have exactly one WorkloadPolicy or WorkloadPolicyProposal, found 0",
		},
		{
			name: "two policies in the file",
			args: func(t *testing.T) []string {
				return []string{writePolicies(t, policy, policy), "--image", "web:1"}
			},
			err: "must have exactly one WorkloadPolicy or WorkloadPolicyProposal, found 2",
		},
		{
			name: "two workloads in the file",
			args: func(t *testing.T) []string {
				return []string{
					writePolicies(t, policy),
					"--workload", wpt.WriteFile(t, deployment("a"), deployment("b")),
				}
			},
			err: `must have exactly one workload, found Deployment "a", Deployment "b"`,
		},
		{
			name: "no container in common",
			args: func(t *testing.T) []string {
				other := newPolicy(t, map[string][]string{"other": {"/usr/bin/other"}})
				return []string{writePolicies(t, other), "--workload", wpt.WriteFile(t, deployment("a"))}
			},
			err: `the policy and Deployment "a" have no container in common`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, err := runWpgen(t, append([]string{"check"}, tt.args(t)...)...)
			require.ErrorContains(t, err, tt.err)
			assert.Empty(t, stdout)
			assert.NotContains(t, stderr, "Loading image")
		})
	}
}
