// Package workloadparse reads Kubernetes workloads from YAML or JSON
// manifests and returns the containers of their pod templates.
package workloadparse

import (
	"fmt"
	"io"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/kubewarden/runtime-enforcer/internal/manifest"
	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
)

// Container is a container of a pod template.
type Container struct {
	Name  string
	Image string
	// Init is true for the entries of initContainers.
	Init bool
}

// Workload is a supported workload found in the input.
type Workload struct {
	Kind      workloadkind.Kind
	Name      string
	Namespace string
	// PodLabels are the labels of the pod template.
	PodLabels map[string]string
	// Containers lists the containers, then the init containers, in the
	// order of the manifest.
	Containers []Container
}

// Skipped is a document of the input that is not a supported workload.
type Skipped struct {
	APIVersion string
	Kind       string
	Name       string
	Reason     string
}

// Parse reads a stream of YAML or JSON documents. It returns the supported
// workloads and the documents that it skipped, in the order of the input.
// Items of a List are handled as separate documents.
func Parse(r io.Reader) ([]Workload, []Skipped, error) {
	var (
		workloads []Workload
		skipped   []Skipped
	)

	err := manifest.ForEachObject(r, func(obj *unstructured.Unstructured) error {
		w, s, err := parseObject(obj)
		if err != nil {
			return err
		}
		if s != nil {
			skipped = append(skipped, *s)
			return nil
		}
		workloads = append(workloads, *w)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return workloads, skipped, nil
}

type templateExtractor func(*unstructured.Unstructured) (*corev1.PodTemplateSpec, error)

// extract returns a templateExtractor that converts the object to T and
// returns its pod template.
func extract[T any](template func(*T) *corev1.PodTemplateSpec) templateExtractor {
	return func(obj *unstructured.Unstructured) (*corev1.PodTemplateSpec, error) {
		var typed T
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &typed); err != nil {
			return nil, err
		}
		return template(&typed), nil
	}
}

// extractorFor returns nil when the kind is not a supported workload.
func extractorFor(gvk schema.GroupVersionKind) templateExtractor {
	switch gvk {
	case appsv1.SchemeGroupVersion.WithKind(workloadkind.Deployment.String()):
		return extract(func(o *appsv1.Deployment) *corev1.PodTemplateSpec { return &o.Spec.Template })
	case appsv1.SchemeGroupVersion.WithKind(workloadkind.ReplicaSet.String()):
		return extract(func(o *appsv1.ReplicaSet) *corev1.PodTemplateSpec { return &o.Spec.Template })
	case appsv1.SchemeGroupVersion.WithKind(workloadkind.DaemonSet.String()):
		return extract(func(o *appsv1.DaemonSet) *corev1.PodTemplateSpec { return &o.Spec.Template })
	case appsv1.SchemeGroupVersion.WithKind(workloadkind.StatefulSet.String()):
		return extract(func(o *appsv1.StatefulSet) *corev1.PodTemplateSpec { return &o.Spec.Template })
	case batchv1.SchemeGroupVersion.WithKind(workloadkind.Job.String()):
		return extract(func(o *batchv1.Job) *corev1.PodTemplateSpec { return &o.Spec.Template })
	case batchv1.SchemeGroupVersion.WithKind(workloadkind.CronJob.String()):
		return extract(func(o *batchv1.CronJob) *corev1.PodTemplateSpec { return &o.Spec.JobTemplate.Spec.Template })
	default:
		return nil
	}
}

func parseObject(obj *unstructured.Unstructured) (*Workload, *Skipped, error) {
	gvk := obj.GroupVersionKind()

	extractor := extractorFor(gvk)
	if extractor == nil {
		return nil, skip(obj, skipReason(gvk)), nil
	}

	if obj.GetName() == "" {
		return nil, nil, fmt.Errorf("%s has no name", gvk.Kind)
	}
	tmpl, err := extractor(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %q: %w", gvk.Kind, obj.GetName(), err)
	}

	w := &Workload{
		Kind:      workloadkind.Kind(gvk.Kind),
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		PodLabels: tmpl.Labels,
	}
	for _, c := range tmpl.Spec.Containers {
		w.Containers = append(w.Containers, Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range tmpl.Spec.InitContainers {
		w.Containers = append(w.Containers, Container{Name: c.Name, Image: c.Image, Init: true})
	}

	if err = w.validate(); err != nil {
		return nil, nil, err
	}
	return w, nil, nil
}

func (w *Workload) validate() error {
	if len(w.Containers) == 0 {
		return fmt.Errorf("%s %q has no containers", w.Kind, w.Name)
	}
	for _, c := range w.Containers {
		if c.Name == "" {
			return fmt.Errorf("%s %q has a container without a name", w.Kind, w.Name)
		}
		if c.Image == "" {
			return fmt.Errorf("%s %q: container %q has no image", w.Kind, w.Name, c.Name)
		}
	}
	return nil
}

func skipReason(gvk schema.GroupVersionKind) string {
	switch {
	case gvk == corev1.SchemeGroupVersion.WithKind(string(workloadkind.Pod)):
		return "runtime-enforcer does not learn policies for bare pods"
	case isWorkloadKind(gvk.Kind):
		return fmt.Sprintf("unsupported apiVersion %q", gvk.GroupVersion().String())
	default:
		return "not a workload"
	}
}

// isWorkloadKind reports if the kind is supported, whatever its apiVersion.
func isWorkloadKind(kind string) bool {
	_, err := workloadkind.Kind(kind).ShortName()
	return err == nil
}

func skip(obj *unstructured.Unstructured, reason string) *Skipped {
	return &Skipped{
		APIVersion: obj.GetAPIVersion(),
		Kind:       obj.GetKind(),
		Name:       obj.GetName(),
		Reason:     reason,
	}
}
