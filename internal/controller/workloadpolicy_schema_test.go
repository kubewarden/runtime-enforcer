package controller_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
)

var _ = Describe("WorkloadPolicy schema", func() {
	const (
		testNS        = "default"
		policyName    = "foreign-root-policy"
		containerName = "main"
	)

	cases := []struct {
		name        string
		foreignRoot v1alpha1.ForeignRootPolicy
		wantInvalid bool
		want        v1alpha1.ForeignRootPolicy
	}{
		{name: "defaults an empty foreignRoot to Deny", want: v1alpha1.ForeignRootDeny},
		{name: "accepts Allow", foreignRoot: v1alpha1.ForeignRootAllow, want: v1alpha1.ForeignRootAllow},
		{name: "accepts Deny", foreignRoot: v1alpha1.ForeignRootDeny, want: v1alpha1.ForeignRootDeny},
		{name: "rejects an unknown value", foreignRoot: "Maybe", wantInvalid: true},
	}

	for _, c := range cases {
		It(c.name, func() {
			policy := &v1alpha1.WorkloadPolicy{
				Name:      policyName,
				Namespace: testNS,
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: policymode.MonitorString,
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						containerName: {
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed:     []string{"/usr/bin/sleep"},
								ForeignRoot: c.foreignRoot,
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, policy)
			if c.wantInvalid {
				Expect(apierrors.IsInvalid(err)).To(BeTrue())
				return
			}
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, policy))).To(Succeed())
			})

			got := &v1alpha1.WorkloadPolicy{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), got)).To(Succeed())
			Expect(got.Spec.RulesByContainer[containerName].Executables.ForeignRoot).To(Equal(c.want))
		})
	}
})
