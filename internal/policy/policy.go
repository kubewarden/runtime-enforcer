package policy

import (
	"fmt"
)

// GetWorkloadSecurityPolicyProposalName returns the name of WorkloadSecurityPolicyProposal
// based on a high level resource and its name.
func GetWorkloadSecurityPolicyProposalName(kind string, resourceName string) (string, error) {
	var shortname string
	switch kind {
	case "Deployment":
		shortname = "deploy"
	case "ReplicaSet":
		shortname = "rs"
	case "DaemonSet":
		shortname = "ds"
	case "CronJob":
		shortname = "cronjob"
	case "Job":
		shortname = "job"
	case "StatefulSet":
		shortname = "sts"
	default:
		return "", fmt.Errorf("unknown kind: %s", kind)
	}
	return shortname + "-" + resourceName, nil
}
