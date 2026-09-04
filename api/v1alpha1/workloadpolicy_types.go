package v1alpha1

import (
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Phase represents the current phase of the workload policy.
// Possible values are:
// - "Transitioning": the policy is in the process of changing its enforcement mode.
// - "Failed": the policy deployment has failed.
// - "Ready": the policy is ready and actively enforced.
type Phase string

const (
	// Transitioning indicates that the policy is in the process of changing its enforcement mode.
	Transitioning Phase = "Transitioning"
	// Failed indicates that the policy deployment has failed.
	Failed Phase = "Failed"
	// Ready indicates that the policy is ready.
	Ready Phase = "Ready"
)

type WorkloadPolicyExecutables struct {
	// allowed defines a list of executables that are allowed to run
	// +kubebuilder:validation:items:Pattern=`^/.*$`
	// +optional
	Allowed []string `json:"allowed,omitempty"`
}

type WorkloadPolicyRules struct {
	// executables defines a security policy for executables.
	// +optional
	Executables WorkloadPolicyExecutables `json:"executables,omitempty"`
}

type WorkloadPolicySpec struct {
	// mode defines the execution mode of this policy. Can be set to
	// either "protect" or "monitor". In "protect" mode, the policy
	// blocks and reports violations, while in "monitor" mode,
	// it only reports violations.
	// +kubebuilder:validation:Enum=monitor;protect
	// +kubebuilder:validation:Required
	Mode string `json:"mode,omitempty"`

	// rulesByContainer specifies for each container the list of rules to apply.
	RulesByContainer map[string]*WorkloadPolicyRules `json:"rulesByContainer,omitempty"`
}

type WorkloadPolicyStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// nodesWithIssues contains the status of each node with issues.
	NodesWithIssues map[string]PolicyStatus `json:"nodesWithIssues,omitempty"`
	// totalNodes is the total number of nodes the policy is applied to.
	TotalNodes int `json:"totalNodes,omitempty"`
	// successfulNodes is the number of nodes where the policy is successfully enforced.
	SuccessfulNodes int `json:"successfulNodes,omitempty"`
	// failedNodes is the number of nodes where the policy enforcement failed.
	FailedNodes int `json:"failedNodes,omitempty"`
	// transitioningNodes is the number of nodes where the policy is transitioning mode.
	TransitioningNodes int `json:"transitioningNodes,omitempty"`
	// nodesTransitioning contains the nodes that are transitioning, including
	// the time at which each node entered the transitioning state.
	NodesTransitioning []PolicyNodeStatus `json:"nodesTransitioning,omitempty"`
	// phase indicates the current phase of the workload policy.
	Phase Phase `json:"phase,omitempty"`
	// violationCount is the total number of unique violation records
	// ever observed for this policy, including those that have already
	// been trimmed out of Violations or cleared because the executable
	// was later added to an allowlist. It is not guaranteed to be strongly
	// consistent and may be temporarily outdated.
	// +kubebuilder:default=0
	// +optional
	ViolationCount int64 `json:"violationCount"`
	// activeViolationCount is the number of currently active (non-cleared)
	// violation records. It is always equal to len(Violations) and is
	// updated in the same status write.
	// +kubebuilder:default=0
	// +optional
	ActiveViolationCount int `json:"activeViolationCount"`
	// violations is the list of the most recent violation records (max maxViolationRecords).
	// Oldest entries are dropped when the limit is reached.
	// +optional
	Violations []ViolationRecord `json:"violations,omitempty"`

	// acknowledgedViolations is the list of the most recent violation records that are acknowledged
	// by users (max maxViolationRecords).
	// Oldest entries are dropped when the limit is reached.
	// +optional
	AcknowledgedViolations []AcknowledgedViolationRecord `json:"acknowledgedViolations,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Active Violations",type=string,JSONPath=`.status.activeViolationCount`
// +kubebuilder:printcolumn:name="Total Violations",type=string,JSONPath=`.status.violationCount`
// +kubebuilder:resource:singular="workloadpolicy",path="workloadpolicies",scope="Namespaced",shortName={wp}
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadPolicy is the Schema for the workloadpolicies API.
type WorkloadPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkloadPolicySpec   `json:"spec,omitempty"`
	Status WorkloadPolicyStatus `json:"status,omitempty"`
}

// NamespacedName returns a string in the form "<namespace>/<name>".
//
// This is useful when storing/retrieving WorkloadPolicy-related state in maps.
func (wp *WorkloadPolicy) NamespacedName() string {
	if wp == nil {
		return ""
	}
	return wp.Namespace + "/" + wp.Name
}

func (wp *WorkloadPolicy) SetPromotedLabel(proposalName string) error {
	if wp == nil {
		return errors.New("WorkloadPolicy is nil")
	}

	// Valid k8s label value must be 63 characters or less.
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	// We catch here the error instead of letting the API server handle it.
	const maxLabelValueLength = 63
	if len(proposalName) > maxLabelValueLength {
		return fmt.Errorf("proposalName %q is too long", proposalName)
	}

	if wp.Labels == nil {
		wp.SetLabels(map[string]string{})
	}

	wp.Labels[PolicyPromotedFromLabelKey] = proposalName
	return nil
}

func (wp *WorkloadPolicy) HasPromotedLabel(proposalName string) bool {
	if wp == nil {
		return false
	}
	return wp.Labels[PolicyPromotedFromLabelKey] == proposalName
}

func (wp *WorkloadPolicy) RecomputeStatus(
	nodes []PolicyNodeStatus,
	scrapedViolations []ViolationRecord,
	now time.Time,
) ([]AcknowledgedViolationRecord, error) {
	if wp == nil {
		return nil, errors.New("WorkloadPolicy is nil")
	}

	// processPolicyNodeStatus recomputes the per-node status. The object already
	// carries the previous status, which is threaded through so that the per-node
	// "since" timestamps are preserved for nodes whose code is unchanged.
	if err := wp.Status.processPolicyNodeStatus(wp.Status, nodes, now); err != nil {
		return nil, fmt.Errorf(
			"failed to compute node status for policy %s: %w",
			wp.NamespacedName(),
			err,
		)
	}

	// Merge scraped violations into the status.
	// we will clear/acknowledge violations after the merge so that the status
	// is coherent across syncs.
	wp.Status.mergeScrapedViolations(scrapedViolations)

	// Stale violations are violations for binaries that
	// are now in the spec.
	wp.clearAllowedViolations()

	// Acknowledge any violations that have been acknowledged
	acknowledged := wp.acknowledgeViolationsFromAnnotations(metav1.Time{Time: now})

	wp.Status.ActiveViolationCount = len(wp.Status.Violations)
	wp.Status.ObservedGeneration = wp.Generation
	return acknowledged, nil
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadPolicyList contains a list of WorkloadPolicy.
type WorkloadPolicyList struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WorkloadPolicy `json:"items"`
}
