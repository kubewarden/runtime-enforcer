// Package policydraft builds WorkloadPolicy drafts and encodes them for
// humans and for kubectl.
package policydraft

import (
	"encoding/json"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

const (
	// FormatYAML encodes the policy as YAML.
	FormatYAML = "yaml"
	// FormatJSON encodes the policy as indented JSON.
	FormatJSON = "json"
)

// New returns a WorkloadPolicy that allows the given executables for each
// container. The keys of executablesByContainer are container names.
func New(
	name, namespace, mode string,
	executablesByContainer map[string][]string,
) (*v1alpha1.WorkloadPolicy, error) {
	if !policymode.IsValid(mode) {
		return nil, fmt.Errorf(
			"invalid mode %q: must be %q or %q",
			mode,
			policymode.MonitorString,
			policymode.ProtectString,
		)
	}

	rules := make(map[string]*v1alpha1.WorkloadPolicyRules, len(executablesByContainer))
	for container, executables := range executablesByContainer {
		rules[container] = &v1alpha1.WorkloadPolicyRules{
			Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: executables},
		}
	}

	return &v1alpha1.WorkloadPolicy{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "WorkloadPolicy",
		Name:       name,
		Namespace:  namespace,
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode:             mode,
			RulesByContainer: rules,
		},
	}, nil
}

// Encode writes the policy to w in the given format. The output does not
// contain the status and the fields that the API server sets.
func Encode(w io.Writer, policy *v1alpha1.WorkloadPolicy, format string) error {
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policy)
	if err != nil {
		return fmt.Errorf("cannot convert the policy: %w", err)
	}
	delete(obj, "status")
	if metadata, ok := obj["metadata"].(map[string]any); ok {
		delete(metadata, "creationTimestamp")
	}

	var data []byte
	switch format {
	case FormatYAML:
		data, err = yaml.Marshal(obj)
	case FormatJSON:
		data, err = json.MarshalIndent(obj, "", "  ")
		data = append(data, '\n')
	default:
		return fmt.Errorf("invalid output format %q: must be %q or %q", format, FormatYAML, FormatJSON)
	}
	if err != nil {
		return fmt.Errorf("cannot encode the policy as %s: %w", format, err)
	}

	_, err = w.Write(data)
	return err
}

// EncodeAll writes the policies to w in the given format. YAML documents are
// divided by "---". JSON objects follow each other, as kubectl accepts.
func EncodeAll(w io.Writer, policies []*v1alpha1.WorkloadPolicy, format string) error {
	for i, policy := range policies {
		if i > 0 && format == FormatYAML {
			if _, err := io.WriteString(w, "---\n"); err != nil {
				return err
			}
		}
		if err := Encode(w, policy, format); err != nil {
			return err
		}
	}
	return nil
}
