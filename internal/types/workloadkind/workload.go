package workloadkind

import "fmt"

type Kind string

const (
	Pod         Kind = "Pod"
	Deployment  Kind = "Deployment"
	DaemonSet   Kind = "DaemonSet"
	StatefulSet Kind = "StatefulSet"
	ReplicaSet  Kind = "ReplicaSet"
	Job         Kind = "Job"
	CronJob     Kind = "CronJob"
	Unknown     Kind = "Unknown"
)

func (k Kind) String() string { return string(k) }

// ShortName returns the short name of the kind used as the prefix of the
// WorkloadPolicyProposal names. Only the kinds that the learning controller
// supports have a short name.
func (k Kind) ShortName() (string, error) {
	switch k {
	case Deployment:
		return "deploy", nil
	case ReplicaSet:
		return "rs", nil
	case DaemonSet:
		return "ds", nil
	case CronJob:
		return "cronjob", nil
	case Job:
		return "job", nil
	case StatefulSet:
		return "sts", nil
	case Pod, Unknown:
		fallthrough
	default:
		return "", fmt.Errorf("unknown kind: %s", k)
	}
}
