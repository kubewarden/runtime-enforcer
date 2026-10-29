package wpgen

import (
	"bytes"
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

func writePolicies(t *testing.T, policies ...*v1alpha1.WorkloadPolicy) string {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, policydraft.EncodeAll(&buf, policies, policydraft.FormatYAML))
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	return path
}

func deploymentWith(containers ...corev1.Container) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: objectMeta("web", "prod"), Spec: appsv1.DeploymentSpec{
		Template: podTemplate(nil, containers...),
	}}
}

func TestCheckCmdClean(t *testing.T) {
	t.Parallel()

	img, initImg := busyboxImage(t), initImage(t)
	workload := deploymentWith(
		corev1.Container{Name: "shell", Image: img},
		corev1.Container{Name: "tools", Image: img},
	)
	workload.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: initImg}}

	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"shell": {"/usr/bin/busybox"},
		"tools": {"/usr/bin/busybox", "/usr/bin/extra"},
		"setup": {"/bin/init"},
	}))

	stdout, stderr, err := runWpgen(t, "check", policy,
		"--workload", wpt.WriteFile(t, workload), "--image-src", "oci-dir")
	require.NoError(t, err)

	assert.Equal(t, fmt.Sprintf(`Policy "deploy-web" (namespace prod):
  container "shell" (image %[1]s):
    all 1 allowed paths are executables in the image
    1 executables of the image are not allowed
  container "tools" (image %[1]s):
    all 2 allowed paths are executables in the image
    0 executables of the image are not allowed
  init container "setup" (image %[2]s):
    all 1 allowed paths are executables in the image
    0 executables of the image are not allowed
`, img, initImg), stdout)
	assert.Equal(t, 1, strings.Count(stderr, fmt.Sprintf("Loading image %q", img)), "each image is scanned once")
}

func TestCheckCmdStalePaths(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"shell": {"/usr/bin/busybox", "/bin/sh", "/usr/bin/sh", "/usr/local/bin/gone"},
	}))

	stdout, _, err := runWpgen(t, "check", policy,
		"--workload", wpt.WriteFile(t, deploymentWith(corev1.Container{Name: "shell", Image: img})),
		"--image-src", "oci-dir")
	require.EqualError(t, err, "3 allowed paths are not executables in the images")

	assert.Equal(t, fmt.Sprintf(`Policy "deploy-web" (namespace prod):
  container "shell" (image %s):
    1 of 4 allowed paths are executables in the image
    3 allowed paths are not executables in the image:
      /bin/sh (symbolic link to /usr/bin/busybox, the enforcer reports /usr/bin/busybox)
      /usr/bin/sh (symbolic link to /usr/bin/busybox, the enforcer reports /usr/bin/busybox)
      /usr/local/bin/gone
    1 executables of the image are not allowed
`, img), stdout)
}

func TestCheckCmdContainerMismatch(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	workload := deploymentWith(
		corev1.Container{Name: "shell", Image: img},
		corev1.Container{Name: "unknown", Image: img},
	)
	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"shell":   {"/usr/bin/busybox"},
		"removed": {"/usr/bin/extra"},
	}))

	stdout, stderr, err := runWpgen(t, "check", policy,
		"--workload", wpt.WriteFile(t, workload), "--image-src", "oci-dir")
	require.NoError(t, err)

	assert.Contains(t, stdout, `container "shell"`)
	assert.NotContains(t, stdout, `container "unknown"`)
	assert.NotContains(t, stdout, `container "removed"`)
	assert.Contains(t, stderr, `The policy has no rules for container "unknown" of Deployment "web"`)
	assert.Contains(t, stderr, `The policy has rules for container "removed", which is not in Deployment "web"`)
}

func TestCheckCmdSkippedKinds(t *testing.T) {
	t.Parallel()

	img := mixedImage(t)
	policy := writePolicies(t, newPolicy(t, map[string][]string{
		"main": {"/usr/bin/app", "/usr/lib/libz.so.1", "/etc/ca.crt"},
	}))

	stdout, _, err := runWpgen(t, "check", policy, "--image", img, "--image-src", "oci-dir")
	require.NoError(t, err, "skipped kinds are not stale")
	assert.Equal(t, fmt.Sprintf(`Policy "deploy-web" (namespace prod):
  container "main" (image %s):
    1 of 3 allowed paths are executables in the image
    1 allowed paths are shared libraries, which wpgen skips unless --include-libraries is set:
      /usr/lib/libz.so.1
    1 allowed paths are neither programs nor scripts, which wpgen skips unless --include-unknown is set:
      /etc/ca.crt
    1 executables of the image are not allowed
`, img), stdout)

	stdout, _, err = runWpgen(t, "check", policy, "--image", img, "--image-src", "oci-dir",
		"--include-libraries", "--include-unknown")
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf(`Policy "deploy-web" (namespace prod):
  container "main" (image %s):
    all 3 allowed paths are executables in the image
    2 executables of the image are not allowed
`, img), stdout)
}

func TestCheckCmdImage(t *testing.T) {
	t.Parallel()

	img := busyboxImage(t)
	single := writePolicies(t, newPolicy(t, map[string][]string{"main": {"/usr/bin/busybox"}}))
	several := writePolicies(t, newPolicy(t, map[string][]string{
		"main":    {"/usr/bin/busybox"},
		"sidecar": {"/usr/bin/extra"},
	}))

	stdout, _, err := runWpgen(t, "check", single, "--image", img, "--image-src", "oci-dir")
	require.NoError(t, err)
	assert.Contains(t, stdout, `container "main"`)

	stdout, _, err = runWpgen(t, "check", several, "--image", img, "--container-name", "sidecar",
		"--image-src", "oci-dir")
	require.NoError(t, err)
	assert.Contains(t, stdout, `container "sidecar"`)
	assert.NotContains(t, stdout, `container "main"`)

	_, _, err = runWpgen(t, "check", several, "--image", img, "--image-src", "oci-dir")
	require.ErrorContains(t, err, "the policy has 2 containers, use --container-name to choose one")

	_, _, err = runWpgen(t, "check", several, "--image", img, "--container-name", "nope", "--image-src", "oci-dir")
	require.ErrorContains(t, err, `the policy has no container "nope"`)
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
	assert.Contains(t, stdout, `Policy "deploy-web" (namespace <none>):`)
	assert.Contains(t, stdout, "all 1 allowed paths are executables in the image")
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
