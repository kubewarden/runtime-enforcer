package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// maxPodNames avoids oversized response.
const maxPodNames = 10

// +kubebuilder:webhook:path=/validate-security-rancher-io-v1alpha1-workloadpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.rancher.io,resources=workloadpolicies,verbs=delete,versions=v1alpha1,name=validate-workloadpolicies.rancher.io,admissionReviewVersions=v1

type PolicyCustomValidator struct {
	Client client.Client
}

var _ admission.Validator[*v1alpha1.WorkloadPolicy] = &PolicyCustomValidator{}

func (v *PolicyCustomValidator) ValidateCreate(
	ctx context.Context,
	policy *v1alpha1.WorkloadPolicy,
) (admission.Warnings, error) {
	logger := log.FromContext(ctx)
	logger.Info("Validation for WorkloadPolicy upon creation", "name", policy.GetName())
	return nil, nil
}

func (v *PolicyCustomValidator) ValidateUpdate(
	ctx context.Context,
	_, newPolicy *v1alpha1.WorkloadPolicy,
) (admission.Warnings, error) {
	logger := log.FromContext(ctx)
	logger.Info("Validation for WorkloadPolicy upon update", "name", newPolicy.GetName())
	return nil, nil
}

func (v *PolicyCustomValidator) ValidateDelete(
	ctx context.Context,
	policy *v1alpha1.WorkloadPolicy,
) (admission.Warnings, error) {
	podList := &metav1.PartialObjectMetadataList{}
	podList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "PodList",
	})

	if err := v.Client.List(ctx, podList,
		client.InNamespace(policy.Namespace),
		client.MatchingLabels{v1alpha1.PolicyLabelKey: policy.Name},
	); err != nil {
		return nil, fmt.Errorf("list pods for WorkloadPolicy %q: %w", policy.Name, err)
	}

	if len(podList.Items) == 0 {
		return nil, nil
	}

	podNames := make([]string, 0, len(podList.Items))
	for _, pod := range podList.Items {
		podNames = append(podNames, pod.Name)
	}

	logger := log.FromContext(ctx)
	logger.Error(nil, "policy deletion denied: policy is still used by pods",
		"policyName", policy.Name,
		"namespace", policy.Namespace,
		"podCount", len(podNames),
		"podNames", podNames,
	)

	return nil, apierrors.NewForbidden(
		schema.GroupResource{
			Group:    "security.rancher.io",
			Resource: "workloadpolicies",
		},
		policy.Name,
		fmt.Errorf(
			"cannot delete WorkloadPolicy %q while %d pod(s) in namespace %q still use it: %s",
			policy.Name,
			len(podNames),
			policy.Namespace,
			listPodNames(podNames),
		),
	)
}

func listPodNames(names []string) string {
	if len(names) == 0 {
		return ""
	}
	if len(names) <= maxPodNames {
		return strings.Join(names, ", ")
	}
	podNames := strings.Join(names[:maxPodNames], ", ")
	return fmt.Sprintf("%s (and %d more)", podNames, len(names)-maxPodNames)
}
