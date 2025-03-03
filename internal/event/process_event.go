package event

import (
	"errors"
	"fmt"

	"github.com/neuvector/runtime-enforcement/internal/policy"
)

type ProcessEvent struct {
	ClusterName    string            `json:"cluster_name"`
	Namespace      string            `json:"namespace"`
	PodID          string            `json:"pod_id"`
	ContainerID    string            `json:"container_id"`
	ContainerName  string            `json:"container_name"`
	ExecutablePath string            `json:"executable_path"`
	Arguments      string            `json:"arguments"`
	Workload       string            `json:"workload"`
	WorkloadKind   string            `json:"workload_kind"`
	Labels         map[string]string `json:"labels"`
	Repeat         int               `json:"repeat"`
}

// TODO: Check if there is a better separator
func (pe *ProcessEvent) Hash() string {
	return fmt.Sprintf("ProcessEvent#%s#%s#%s#%s#%s",
		pe.Namespace, pe.PodID, pe.ContainerID, pe.ContainerName, pe.ExecutablePath)
}

func (pe *ProcessEvent) Aggregate(_ AggregatableEvent) error {
	pe.Repeat++
	return nil
}

// GetProposalName retrieves the name of WorkloadSecurityPolicyProposal used in behavior learning.
func (pe *ProcessEvent) GetProposalName() (string, error) {
	if pe.Workload != "" && pe.WorkloadKind != "" {
		return policy.GetWorkloadSecurityPolicyProposalName(pe.WorkloadKind, pe.Workload)
	}
	return "", errors.New("no workload information is assigned for this event")
}

// GetNamespace returns the kubernetes namespace name where this process event happens.
func (pe *ProcessEvent) GetNamespace() string {
	return pe.Namespace
}

func (pe *ProcessEvent) GetExecutablePath() string {
	return pe.ExecutablePath
}
