package policydraft

import (
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/manifest"
)

const (
	policyKind   = "WorkloadPolicy"
	proposalKind = "WorkloadPolicyProposal"
)

// Skipped is a document of the input that is not a policy or a proposal.
type Skipped struct {
	APIVersion string
	Kind       string
	Name       string
}

// Decode reads a stream of YAML or JSON documents and returns the
// WorkloadPolicy and WorkloadPolicyProposal objects in it, in order. A
// proposal is returned as a policy with the same name, namespace and rules.
// The other documents are returned as skipped.
func Decode(r io.Reader) ([]*v1alpha1.WorkloadPolicy, []Skipped, error) {
	var (
		policies []*v1alpha1.WorkloadPolicy
		skipped  []Skipped
	)

	err := manifest.ForEachObject(r, func(obj *unstructured.Unstructured) error {
		var (
			policy *v1alpha1.WorkloadPolicy
			err    error
		)
		switch obj.GroupVersionKind() {
		case v1alpha1.GroupVersion.WithKind(policyKind):
			policy, err = decodePolicy(obj)
		case v1alpha1.GroupVersion.WithKind(proposalKind):
			policy, err = decodeProposal(obj)
		default:
			skipped = append(skipped, Skipped{
				APIVersion: obj.GetAPIVersion(),
				Kind:       obj.GetKind(),
				Name:       obj.GetName(),
			})
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s %q: %w", obj.GetKind(), obj.GetName(), err)
		}
		policies = append(policies, policy)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return policies, skipped, nil
}

func decodePolicy(obj *unstructured.Unstructured) (*v1alpha1.WorkloadPolicy, error) {
	policy := &v1alpha1.WorkloadPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func decodeProposal(obj *unstructured.Unstructured) (*v1alpha1.WorkloadPolicy, error) {
	proposal := &v1alpha1.WorkloadPolicyProposal{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, proposal); err != nil {
		return nil, err
	}
	return &v1alpha1.WorkloadPolicy{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       policyKind,
		Name:       proposal.Name,
		Namespace:  proposal.Namespace,
		Spec:       v1alpha1.WorkloadPolicySpec{RulesByContainer: proposal.Spec.RulesByContainer},
	}, nil
}
