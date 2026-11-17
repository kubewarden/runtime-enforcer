package proposalutils

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
)

// GetWorkloadPolicyProposalName returns the name of WorkloadPolicyProposal
// based on a high level resource and its name.
func GetWorkloadPolicyProposalName(kind string, resourceName string) (string, error) {
	shortname, err := workloadkind.Kind(kind).ShortName()
	if err != nil {
		return "", err
	}
	ret := shortname + "-" + resourceName

	// The max name length in k8s
	if len(ret) > validation.DNS1123SubdomainMaxLength {
		return "", fmt.Errorf("the name %s exceeds the maximum name length", ret)
	}

	return shortname + "-" + resourceName, nil
}

func HasProposalBeenPromoted(
	ctx context.Context,
	c client.Client,
	namespace, proposalName string,
) (bool, error) {
	var workloadPolicies securityv1alpha1.WorkloadPolicyList
	if err := c.List(
		ctx,
		&workloadPolicies,
		client.InNamespace(namespace),
		client.MatchingLabels{
			securityv1alpha1.PolicyPromotedFromLabelKey: proposalName,
		},
	); err != nil {
		return false, err
	}

	return len(workloadPolicies.Items) > 0, nil
}
