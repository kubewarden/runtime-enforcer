package workloadparse_test

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
	"github.com/kubewarden/runtime-enforcer/internal/workloadparse"
	wpt "github.com/kubewarden/runtime-enforcer/internal/workloadparse/workloadparsetest"
)

func meta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace}
}

func podSpec(containers ...corev1.Container) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: containers}}
}

func TestParseSupportedKinds(t *testing.T) {
	t.Parallel()

	template := corev1.PodTemplateSpec{
		Labels: map[string]string{"app": "web"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init", Image: "busybox:1.36"}},
			Containers: []corev1.Container{
				{Name: "web", Image: "nginx:1.27", Ports: []corev1.ContainerPort{{ContainerPort: 80}}},
				{Name: "sidecar", Image: "envoy:1.30"},
			},
		},
	}
	expectedContainers := []workloadparse.Container{
		{Name: "web", Image: "nginx:1.27"},
		{Name: "sidecar", Image: "envoy:1.30"},
		{Name: "init", Image: "busybox:1.36", Init: true},
	}
	om := meta("web", "prod")

	tests := []struct {
		kind workloadkind.Kind
		obj  runtime.Object
	}{
		{workloadkind.Deployment, &appsv1.Deployment{ObjectMeta: om, Spec: appsv1.DeploymentSpec{Template: template}}},
		{workloadkind.ReplicaSet, &appsv1.ReplicaSet{ObjectMeta: om, Spec: appsv1.ReplicaSetSpec{Template: template}}},
		{workloadkind.DaemonSet, &appsv1.DaemonSet{ObjectMeta: om, Spec: appsv1.DaemonSetSpec{Template: template}}},
		{
			workloadkind.StatefulSet,
			&appsv1.StatefulSet{ObjectMeta: om, Spec: appsv1.StatefulSetSpec{Template: template}},
		},
		{workloadkind.Job, &batchv1.Job{ObjectMeta: om, Spec: batchv1.JobSpec{Template: template}}},
		{workloadkind.CronJob, &batchv1.CronJob{ObjectMeta: om, Spec: batchv1.CronJobSpec{
			Schedule:    "*/5 * * * *",
			JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: template}},
		}}},
	}

	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			t.Parallel()

			workloads, skipped, err := workloadparse.Parse(wpt.Manifest(t, tt.obj))
			require.NoError(t, err)
			assert.Empty(t, skipped)
			require.Len(t, workloads, 1)

			w := workloads[0]
			assert.Equal(t, tt.kind, w.Kind)
			assert.Equal(t, "web", w.Name)
			assert.Equal(t, "prod", w.Namespace)
			assert.Equal(t, map[string]string{"app": "web"}, w.PodLabels)
			assert.Equal(t, expectedContainers, w.Containers)
		})
	}
}

func TestParseSkipsDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input func(t *testing.T) io.Reader
		// skipped is nil when the document produces nothing.
		skipped *workloadparse.Skipped
	}{
		{
			name: "not a workload",
			input: func(t *testing.T) io.Reader {
				return wpt.Manifest(t, &corev1.Service{ObjectMeta: meta("web", "")})
			},
			skipped: &workloadparse.Skipped{APIVersion: "v1", Kind: "Service", Name: "web", Reason: "not a workload"},
		},
		{
			name: "bare pod",
			input: func(t *testing.T) io.Reader {
				return wpt.Manifest(t, &corev1.Pod{ObjectMeta: meta("debug", ""), Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "debug", Image: "busybox"}},
				}})
			},
			skipped: &workloadparse.Skipped{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       "debug",
				Reason:     "runtime-enforcer does not learn policies for bare pods",
			},
		},
		{
			// The client-go scheme does not know extensions/v1beta1.
			name: "unsupported apiVersion",
			input: func(_ *testing.T) io.Reader {
				return strings.NewReader(`apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: legacy
`)
			},
			skipped: &workloadparse.Skipped{
				APIVersion: "extensions/v1beta1",
				Kind:       "Deployment",
				Name:       "legacy",
				Reason:     `unsupported apiVersion "extensions/v1beta1"`,
			},
		},
		{
			name: "empty input",
			input: func(_ *testing.T) io.Reader {
				return strings.NewReader("")
			},
		},
		{
			name: "comment only",
			input: func(_ *testing.T) io.Reader {
				return strings.NewReader("# a comment only document\n")
			},
		},
		{
			name: "empty documents",
			input: func(_ *testing.T) io.Reader {
				return strings.NewReader("---\n---\n")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			workloads, skipped, err := workloadparse.Parse(tt.input(t))
			require.NoError(t, err)
			assert.Empty(t, workloads)

			if tt.skipped == nil {
				assert.Empty(t, skipped)
				return
			}
			assert.Equal(t, []workloadparse.Skipped{*tt.skipped}, skipped)
		})
	}
}

func TestParseMultipleDocuments(t *testing.T) {
	t.Parallel()

	api := corev1.Container{Name: "api", Image: "ghcr.io/example/api:2.3.0"}
	input := wpt.Manifest(t,
		&appsv1.Deployment{ObjectMeta: meta("api", ""), Spec: appsv1.DeploymentSpec{Template: podSpec(api)}},
		&corev1.Service{ObjectMeta: meta("api", "")},
		&batchv1.Job{ObjectMeta: meta("migrate", ""), Spec: batchv1.JobSpec{Template: podSpec(api)}},
	)

	workloads, skipped, err := workloadparse.Parse(input)
	require.NoError(t, err)

	require.Len(t, workloads, 2)
	assert.Equal(t, workloadkind.Deployment, workloads[0].Kind)
	assert.Equal(t, "api", workloads[0].Name)
	assert.Equal(t, workloadkind.Job, workloads[1].Kind)
	assert.Equal(t, "migrate", workloads[1].Name)

	require.Len(t, skipped, 1)
	assert.Equal(t, "Service", skipped[0].Kind)
}

func TestParseList(t *testing.T) {
	t.Parallel()

	list := &corev1.List{Items: []runtime.RawExtension{
		{Object: wpt.WithGVK(t, &appsv1.DaemonSet{
			ObjectMeta: meta("agent", "kube-system"),
			Spec:       appsv1.DaemonSetSpec{Template: podSpec(corev1.Container{Name: "agent", Image: "agent:1"})},
		})},
		{Object: wpt.WithGVK(t, &corev1.ConfigMap{ObjectMeta: meta("agent-config", "")})},
	}}

	workloads, skipped, err := workloadparse.Parse(wpt.Manifest(t, list))
	require.NoError(t, err)

	require.Len(t, workloads, 1)
	assert.Equal(t, workloadkind.DaemonSet, workloads[0].Kind)
	assert.Equal(t, "agent", workloads[0].Name)
	assert.Equal(t, "kube-system", workloads[0].Namespace)
	require.Len(t, skipped, 1)
	assert.Equal(t, "ConfigMap", skipped[0].Kind)
}

func TestParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input func(t *testing.T) io.Reader
		err   string
	}{
		{
			name: "workload without a name",
			input: func(t *testing.T) io.Reader {
				return wpt.Manifest(t, &appsv1.Deployment{Spec: appsv1.DeploymentSpec{
					Template: podSpec(corev1.Container{Name: "api", Image: "api:1"}),
				}})
			},
			err: "document 1: Deployment has no name",
		},
		{
			name: "container without an image",
			input: func(t *testing.T) io.Reader {
				return wpt.Manifest(t,
					&corev1.ConfigMap{ObjectMeta: meta("first", "")},
					&appsv1.Deployment{ObjectMeta: meta("api", ""), Spec: appsv1.DeploymentSpec{
						Template: podSpec(corev1.Container{Name: "api"}),
					}},
				)
			},
			err: `document 2: Deployment "api": container "api" has no image`,
		},
		{
			name: "workload without containers",
			input: func(t *testing.T) io.Reader {
				return wpt.Manifest(t, &appsv1.StatefulSet{ObjectMeta: meta("db", "")})
			},
			err: `document 1: StatefulSet "db" has no containers`,
		},
		{
			name: "invalid YAML",
			input: func(_ *testing.T) io.Reader {
				return strings.NewReader("apiVersion: apps/v1\nkind: [")
			},
			err: "document 1:",
		},
		{
			name: "field with the wrong type",
			input: func(_ *testing.T) io.Reader {
				return strings.NewReader(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers: "not a list"
`)
			},
			err: `document 1: Deployment "api":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := workloadparse.Parse(tt.input(t))
			require.ErrorContains(t, err, tt.err)
		})
	}
}
