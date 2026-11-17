package policydraft_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/policydraft"
)

func toYAML(t *testing.T, objs ...any) io.Reader {
	t.Helper()

	var buf bytes.Buffer
	for _, obj := range objs {
		data, err := yaml.Marshal(obj)
		require.NoError(t, err)
		buf.WriteString("---\n")
		buf.Write(data)
	}
	return &buf
}

func rules(paths ...string) map[string]*v1alpha1.WorkloadPolicyRules {
	return map[string]*v1alpha1.WorkloadPolicyRules{
		"app": {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: paths}},
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()

	policy, err := policydraft.New("deploy-web", "prod", "protect", map[string][]string{"app": {"/usr/bin/app"}})
	require.NoError(t, err)

	proposal := &v1alpha1.WorkloadPolicyProposal{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "WorkloadPolicyProposal",
		Name:       "deploy-api",
		Namespace:  "prod",
		Spec:       v1alpha1.WorkloadPolicyProposalSpec{RulesByContainer: rules("/usr/bin/api")},
	}
	namespace := &corev1.Namespace{
		APIVersion: "v1",
		Kind:       "Namespace",
		Name:       "prod",
	}

	policies, skipped, err := policydraft.Decode(toYAML(t, namespace, policy, proposal))
	require.NoError(t, err)

	require.Len(t, policies, 2)
	assert.Equal(t, "deploy-web", policies[0].Name)
	assert.Equal(t, "prod", policies[0].Namespace)
	assert.Equal(t, policy.Spec, policies[0].Spec)

	assert.Equal(t, "deploy-api", policies[1].Name)
	assert.Equal(t, "prod", policies[1].Namespace)
	assert.Equal(t, rules("/usr/bin/api"), policies[1].Spec.RulesByContainer)

	assert.Equal(t, []policydraft.Skipped{{APIVersion: "v1", Kind: "Namespace", Name: "prod"}}, skipped)
}

func TestDecodeErrors(t *testing.T) {
	t.Parallel()

	_, _, err := policydraft.Decode(strings.NewReader(`apiVersion: runtimeenforcer.kubewarden.io/v1alpha1
kind: WorkloadPolicy
metadata:
  name: broken
spec:
  rulesByContainer: "not a map"
`))
	require.ErrorContains(t, err, `document 1: WorkloadPolicy "broken":`)
}
