package wpgen

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	ist "github.com/kubewarden/runtime-enforcer/internal/imagescan/imagescantest"
	wpt "github.com/kubewarden/runtime-enforcer/internal/workloadparse/workloadparsetest"
)

func runWpgenWithStdin(t *testing.T, stdin io.Reader, args ...string) (string, string, error) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetArgs(args)
	cmd.SetIn(stdin)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.ExecuteContext(t.Context())
	return stdout.String(), stderr.String(), err
}

func appImage(t *testing.T) string {
	t.Helper()

	return ist.WriteOCIDir(t, ist.NewLayer(t,
		ist.Dir("usr/"), ist.Dir("usr/bin/"),
		ist.Reg("usr/bin/api", 0o755),
		ist.Reg("usr/bin/migrate", 0o755),
	))
}

func initImage(t *testing.T) string {
	t.Helper()

	return ist.WriteOCIDir(t, ist.NewLayer(t, ist.Dir("bin/"), ist.Reg("bin/init", 0o755)))
}

func objectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace}
}

// podTemplate returns a pod template with the given labels and containers.
func podTemplate(labels map[string]string, containers ...corev1.Container) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{
		Labels: labels,
		Spec:   corev1.PodSpec{Containers: containers},
	}
}

func policyLabel(policyName string) map[string]string {
	return map[string]string{v1alpha1.PolicyLabelKey: policyName}
}

func TestWorkloadCmd(t *testing.T) {
	t.Parallel()

	app, initImg := appImage(t), initImage(t)
	web := podTemplate(nil,
		corev1.Container{Name: "api", Image: app},
		corev1.Container{Name: "worker", Image: app},
	)
	web.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: initImg}}

	manifest := wpt.WriteFile(t,
		&corev1.Service{ObjectMeta: objectMeta("web", "")},
		&corev1.Pod{ObjectMeta: objectMeta("debug", ""), Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "debug", Image: app}},
		}},
		&appsv1.Deployment{ObjectMeta: objectMeta("web", "prod"), Spec: appsv1.DeploymentSpec{Template: web}},
	)

	stdout, stderr, err := runWpgen(t, "workload", manifest, "--image-src", "oci-dir")
	require.NoError(t, err)

	assert.Equal(t, `apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: deploy-web
  namespace: prod
spec:
  mode: monitor
  rulesByContainer:
    api:
      executables:
        allowed:
        - /usr/bin/api
        - /usr/bin/migrate
    setup:
      executables:
        allowed:
        - /bin/init
    worker:
      executables:
        allowed:
        - /usr/bin/api
        - /usr/bin/migrate
`, stdout)

	assert.Contains(t, stderr, `Skipping Service "web" (v1): not a workload`)
	assert.Contains(t, stderr, `Skipping Pod "debug" (v1): runtime-enforcer does not learn policies for bare pods`)
	assert.Equal(t, 1, strings.Count(stderr, fmt.Sprintf("Loading image %q", app)), "each image is scanned once")
	assert.Equal(t, 1, strings.Count(stderr, fmt.Sprintf("Loading image %q", initImg)))
	assert.Contains(t, stderr, "Deployment web (namespace prod), policy deploy-web\n")
	for _, label := range []string{"│ api ", "│ worker ", "│ setup (init) "} {
		assert.Contains(t, stderr, label, "the summary has a row for each container")
	}
	assert.Contains(t, stderr, "Add this label to the pod template of Deployment web:\n"+
		"  runtimeenforcer.kubewarden.io/policy: deploy-web\n")
}

func TestWorkloadCmdFromStdin(t *testing.T) {
	t.Parallel()

	app := appImage(t)
	manifest := wpt.Manifest(t,
		&appsv1.StatefulSet{ObjectMeta: objectMeta("db", ""), Spec: appsv1.StatefulSetSpec{
			Template: podTemplate(policyLabel("database"), corev1.Container{Name: "db", Image: app}),
		}},
		&batchv1.CronJob{ObjectMeta: objectMeta("backup", ""), Spec: batchv1.CronJobSpec{
			Schedule: "@daily",
			JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
				Template: podTemplate(nil, corev1.Container{Name: "backup", Image: app}),
			}},
		}},
	)

	stdout, stderr, err := runWpgenWithStdin(t, manifest,
		"workload", "-", "--image-src", "oci-dir", "--mode", "protect", "--warn-threshold", "1")
	require.NoError(t, err)

	assert.Equal(t, `apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: database
spec:
  mode: protect
  rulesByContainer:
    db:
      executables:
        allowed:
        - /usr/bin/api
        - /usr/bin/migrate
---
apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: cronjob-backup
spec:
  mode: protect
  rulesByContainer:
    backup:
      executables:
        allowed:
        - /usr/bin/api
        - /usr/bin/migrate
`, stdout)

	assert.Contains(t, stderr, "StatefulSet db (namespace <none>), policy database\n")
	assert.Contains(
		t,
		stderr,
		"The pod template already has the label runtimeenforcer.kubewarden.io/policy: database\n",
	)
	assert.Contains(t, stderr, "CronJob backup (namespace <none>), policy cronjob-backup\n")
	assert.Contains(t, stderr, "WARNING: container backup allows 2 executables.")
}

func TestWorkloadCmdJSON(t *testing.T) {
	t.Parallel()

	app := appImage(t)
	manifest := wpt.WriteFile(t,
		&appsv1.DaemonSet{ObjectMeta: objectMeta("agent", ""), Spec: appsv1.DaemonSetSpec{
			Template: podTemplate(nil, corev1.Container{Name: "agent", Image: app}),
		}},
		&batchv1.Job{ObjectMeta: objectMeta("migrate", ""), Spec: batchv1.JobSpec{
			Template: podTemplate(nil, corev1.Container{Name: "migrate", Image: app}),
		}},
	)

	stdout, _, err := runWpgen(t, "workload", manifest, "--image-src", "oci-dir", "-o", "json")
	require.NoError(t, err)
	assert.Contains(t, stdout, `"name": "ds-agent"`)
	assert.Contains(t, stdout, `"name": "job-migrate"`)
	assert.NotContains(t, stdout, "---")
}

func TestWorkloadCmdErrors(t *testing.T) {
	t.Parallel()

	deployment := func(name string, labels map[string]string) *appsv1.Deployment {
		return &appsv1.Deployment{ObjectMeta: objectMeta(name, ""), Spec: appsv1.DeploymentSpec{
			Template: podTemplate(labels, corev1.Container{Name: name, Image: name + ":1"}),
		}}
	}

	tests := []struct {
		name string
		objs []runtime.Object
		args []string
		err  string
	}{
		{
			name: "no supported workload",
			objs: []runtime.Object{&corev1.ConfigMap{ObjectMeta: objectMeta("config", "")}},
			err:  "no supported workload found in",
		},
		{
			name: "two workloads with the same policy",
			objs: []runtime.Object{
				deployment("a", policyLabel("shared")),
				deployment("b", policyLabel("shared")),
			},
			err: `Deployment "a" and Deployment "b" both use the policy "shared" in the same namespace`,
		},
		{
			name: "invalid policy name in the label",
			objs: []runtime.Object{deployment("a", policyLabel("Not_Valid"))},
			err:  `Deployment "a": invalid policy name "Not_Valid"`,
		},
		{
			name: "invalid flags",
			args: []string{"--mode", "enforce", "--image-src", "nope"},
			err:  `invalid mode "enforce"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			args := append([]string{"workload", wpt.WriteFile(t, tt.objs...)}, tt.args...)
			stdout, stderr, err := runWpgen(t, args...)
			require.ErrorContains(t, err, tt.err)
			assert.Empty(t, stdout)
			assert.NotContains(t, stderr, "Loading image")
		})
	}
}

func TestWorkloadCmdMissingFile(t *testing.T) {
	t.Parallel()

	_, _, err := runWpgen(t, "workload", filepath.Join(t.TempDir(), "missing.yaml"))
	require.ErrorContains(t, err, "missing.yaml")
}
