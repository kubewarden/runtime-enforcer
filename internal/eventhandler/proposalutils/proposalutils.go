package proposalutils

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func getKindShortName(kind string) (string, error) {
	var shortname string
	switch workloadkind.Kind(kind) {
	case workloadkind.Deployment:
		shortname = "deploy"
	case workloadkind.ReplicaSet:
		shortname = "rs"
	case workloadkind.DaemonSet:
		shortname = "ds"
	case workloadkind.CronJob:
		shortname = "cronjob"
	case workloadkind.Job:
		shortname = "job"
	case workloadkind.StatefulSet:
		shortname = "sts"
	case workloadkind.Pod:
		fallthrough
	case workloadkind.Unknown:
		fallthrough
	default:
		return "", fmt.Errorf("unknown kind: %s", kind)
	}
	return shortname, nil
}

// GetWorkloadPolicyProposalName returns the name of WorkloadPolicyProposal
// based on a high level resource and its name.
func GetWorkloadPolicyProposalName(kind string, resourceName string) (string, error) {
	var shortname string
	var err error
	if shortname, err = getKindShortName(kind); err != nil {
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
