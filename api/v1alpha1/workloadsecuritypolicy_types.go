package v1alpha1

import (
	"fmt"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	tetragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PolicyMode string

const (
	MonitorMode = PolicyMode("monitor")
	ProtectMode = PolicyMode("protect")
)

const (
	// DeployCondition is a condition set when WorkloadSecurityPolicy controller has
	// deployed the policy to the system.
	DeployCondition = "Deployed"

	// SyncFailedReason is set when the reconcile fails.
	SyncFailedReason = "SyncFailed"

	DeployedState = "Deployed"
	ErrorState    = "Error"
)

type WorkloadSecurityPolicyExecutables struct {
	// allowed defines a list of executables that are allowed to run
	// +optional
	Allowed []string `json:"allowed,omitempty"`
	// allowedPrefixes defines a list of prefix with which executables are allowed to run
	// +optional
	AllowedPrefixes []string `json:"allowedPrefixes,omitempty"`
}

type WorkloadSecurityPolicyRules struct {
	// executables defines a security policy used for executables.
	// +optional
	Executables WorkloadSecurityPolicyExecutables `json:"executables,omitempty"`
}

type WorkloadSecurityPolicySpec struct {
	// mode decides the behavior of this policy.
	// +kubebuilder:validation:Enum=monitor;protect
	// +kubebuilder:validation:Required
	Mode PolicyMode `json:"mode,omitempty"`

	// selector is a kubernetes label selector used to match
	// workloads using its pod labels.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// rules specifies the rules this policy contains
	Rules WorkloadSecurityPolicyRules `json:"rules,omitempty"`

	// severity specifies the severity when this policy is violated.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	// +optional
	Severity int `json:"severity"`

	// tags field is used to label this policy and its associated security events
	//
	// +kubebuilder:validation:MaxItems=12
	// +optional
	Tags []string `json:"tags"`

	// message defines the human readable message that will show up in security events
	//
	// +kubebuilder:validation:MaxLength=200
	// +optional
	Message string `json:"message"`
}

func (spec *WorkloadSecurityPolicySpec) intoTetragonKProbeSelector() tetragonv1alpha1.KProbeSelector {
	var selector tetragonv1alpha1.KProbeSelector

	if spec.Mode == ProtectMode {
		selector.MatchActions = []tetragonv1alpha1.ActionSelector{
			{
				Action:   "Override",
				ArgError: -1,
			},
		}
	}

	if len(spec.Rules.Executables.Allowed) > 0 {
		selector.MatchArgs = append(selector.MatchArgs, tetragonv1alpha1.ArgSelector{
			Index:    0,
			Operator: "NotEqual",
			Values:   spec.Rules.Executables.Allowed,
		})
	}
	if len(spec.Rules.Executables.AllowedPrefixes) > 0 {
		selector.MatchArgs = append(selector.MatchArgs, tetragonv1alpha1.ArgSelector{
			Index:    0,
			Operator: "NotPrefix",
			Values:   spec.Rules.Executables.AllowedPrefixes,
		})
	}

	return selector
}

func (spec *WorkloadSecurityPolicySpec) intoTetragonPodSelector() *slimv1.LabelSelector {
	if spec.Selector == nil {
		return nil
	}

	selector := slimv1.LabelSelector{
		MatchLabels: spec.Selector.MatchLabels,
	}

	for _, labelSelectorRequirement := range spec.Selector.MatchExpressions {
		selector.MatchExpressions = append(selector.MatchExpressions, slimv1.LabelSelectorRequirement{
			Key:      labelSelectorRequirement.Key,
			Operator: slimv1.LabelSelectorOperator(labelSelectorRequirement.Operator),
			Values:   labelSelectorRequirement.Values,
		})
	}

	return &selector
}

func (spec *WorkloadSecurityPolicySpec) intoTetragonKProbeSpec() tetragonv1alpha1.KProbeSpec {
	return tetragonv1alpha1.KProbeSpec{
		Call:    "security_bprm_creds_for_exec",
		Syscall: false,
		Args: []tetragonv1alpha1.KProbeArg{
			{
				Index: 0,
				Type:  "linux_binprm",
			},
		},
		Selectors: []tetragonv1alpha1.KProbeSelector{
			spec.intoTetragonKProbeSelector(),
		},
		Tags:    spec.Tags,
		Message: fmt.Sprintf("[%d] %s", spec.Severity, spec.Message),
	}
}

func (spec *WorkloadSecurityPolicySpec) IntoTetragonPolicySpec() tetragonv1alpha1.TracingPolicySpec {
	// KProbe only for now
	return tetragonv1alpha1.TracingPolicySpec{
		KProbes: []tetragonv1alpha1.KProbeSpec{
			spec.intoTetragonKProbeSpec(),
		},
		Options: []tetragonv1alpha1.OptionSpec{
			{
				Name:  "disable-kprobe-multi",
				Value: "1",
			},
		},
		PodSelector: spec.intoTetragonPodSelector(),
	}
}

type WorkloadSecurityPolicyStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	Conditions []metav1.Condition `json:"conditions,omitempty"`

	State  string `json:"state,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Reason",type=string,priority=1,JSONPath=`.status.reason`
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadSecurityPolicy is the Schema for the workloadsecuritypolicies API.
type WorkloadSecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkloadSecurityPolicySpec   `json:"spec,omitempty"`
	Status WorkloadSecurityPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadSecurityPolicyList contains a list of WorkloadSecurityPolicy.
type WorkloadSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WorkloadSecurityPolicy `json:"items"`
}

//nolint:gochecknoinits // Generated by kubebuilder
func init() {
	SchemeBuilder.Register(&WorkloadSecurityPolicy{}, &WorkloadSecurityPolicyList{})
}
