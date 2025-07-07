package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterWorkloadSecurityPolicySpec defines the desired state of ClusterWorkloadSecurityPolicy.
type ClusterWorkloadSecurityPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of ClusterWorkloadSecurityPolicy. Edit clusterworkloadsecuritypolicy_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// ClusterWorkloadSecurityPolicyStatus defines the observed state of ClusterWorkloadSecurityPolicy.
type ClusterWorkloadSecurityPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ClusterWorkloadSecurityPolicy is the Schema for the clusterworkloadsecuritypolicies API.
type ClusterWorkloadSecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterWorkloadSecurityPolicySpec   `json:"spec,omitempty"`
	Status ClusterWorkloadSecurityPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterWorkloadSecurityPolicyList contains a list of ClusterWorkloadSecurityPolicy.
type ClusterWorkloadSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterWorkloadSecurityPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterWorkloadSecurityPolicy{}, &ClusterWorkloadSecurityPolicyList{})
}
