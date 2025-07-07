package controller_test

import (
	"context"

	tragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	. "github.com/onsi/ginkgo/v2" //nolint:revive // Required for testing
	. "github.com/onsi/gomega"    //nolint:revive // Required for testing

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/controller"
)

var _ = Describe("ClusterWorkloadSecurityPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name: resourceName,
		}
		clusterworkloadsecuritypolicy := &securityv1alpha1.ClusterWorkloadSecurityPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind ClusterWorkloadSecurityPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, clusterworkloadsecuritypolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &securityv1alpha1.ClusterWorkloadSecurityPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: resourceName,
					},
					Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
						Mode: "monitor",
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "ubuntu",
							},
						},
						Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
							Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
								Allowed: []string{
									"/usr/bin/sleep",
								},
								AllowedPrefixes: []string{
									"/bin/",
								},
							},
						},
						Severity: 10,
						Tags: []string{
							"tag",
						},
						Message: "TEST_RULE",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &securityv1alpha1.ClusterWorkloadSecurityPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance ClusterWorkloadSecurityPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")

			resource := &securityv1alpha1.ClusterWorkloadSecurityPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			controllerReconciler := &controller.ClusterWorkloadSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var tracingpolicy tragonv1alpha1.TracingPolicy

			// Getting TracingPolicyNamespaced with the same name.
			err = k8sClient.Get(ctx, typeNamespacedName, &tracingpolicy)
			Expect(err).NotTo(HaveOccurred())

			Expect(tracingpolicy.Spec.PodSelector.MatchLabels).To(Equal(resource.Spec.Selector.MatchLabels))
			Expect(len(tracingpolicy.Spec.KProbes)).To(Equal(1))
			Expect(tracingpolicy.Spec.KProbes[0].Message).To(Equal("[10] TEST_RULE"))
			Expect(tracingpolicy.Spec.KProbes[0].Tags).To(Equal([]string{"tag"}))
		})

		It("should generate Tetragon TracingPolicy correctly", func() {
			By("calling GenerateKProbeEnforcePolicy")
			tcs := []struct {
				Name     string
				Policy   securityv1alpha1.ClusterWorkloadSecurityPolicy
				Expected tragonv1alpha1.KProbeSpec
			}{
				{
					Name: "Test protect mode",
					Policy: securityv1alpha1.ClusterWorkloadSecurityPolicy{
						Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
							Mode:     string(securityv1alpha1.ProtectMode),
							Selector: &metav1.LabelSelector{},
							Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
								Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
									Allowed: []string{
										"/usr/bin/sleep",
									},
									AllowedPrefixes: []string{},
								},
							},
							Severity: 0,
							Tags:     []string{},
							Message:  "",
						},
					},
					Expected: tragonv1alpha1.KProbeSpec{
						Call:    "security_bprm_creds_for_exec",
						Syscall: false,
						Args: []tragonv1alpha1.KProbeArg{
							{
								Index: 0,
								Type:  "linux_binprm",
							},
						},
						Selectors: []tragonv1alpha1.KProbeSelector{
							{
								MatchArgs: []tragonv1alpha1.ArgSelector{
									{
										Index:    0,
										Operator: "NotEqual",
										Values:   []string{"/usr/bin/sleep"},
									},
								},
								MatchActions: []tragonv1alpha1.ActionSelector{
									{
										Action:   "Override",
										ArgError: -1,
									},
								},
							},
						},
					},
				},
				{
					Name: "Test monitor mode",
					Policy: securityv1alpha1.ClusterWorkloadSecurityPolicy{
						Spec: securityv1alpha1.WorkloadSecurityPolicySpec{
							Mode:     string(securityv1alpha1.MonitorMode),
							Selector: &metav1.LabelSelector{},
							Rules: securityv1alpha1.WorkloadSecurityPolicyRules{
								Executables: securityv1alpha1.WorkloadSecurityPolicyExecutables{
									Allowed: []string{
										"/usr/bin/sleep",
									},
									AllowedPrefixes: []string{},
								},
							},
							Severity: 0,
							Tags:     []string{},
							Message:  "",
						},
					},
					Expected: tragonv1alpha1.KProbeSpec{
						Call:    "security_bprm_creds_for_exec",
						Syscall: false,
						Args: []tragonv1alpha1.KProbeArg{
							{
								Index: 0,
								Type:  "linux_binprm",
							},
						},
						Selectors: []tragonv1alpha1.KProbeSelector{
							{
								MatchArgs: []tragonv1alpha1.ArgSelector{
									{
										Index:    0,
										Operator: "NotEqual",
										Values:   []string{"/usr/bin/sleep"},
									},
								},
							},
						},
					},
				},
			}

			for _, tc := range tcs {
				log := log.FromContext(ctx)
				log.Info(tc.Name)
				kprobespec, err := controller.GenerateKProbeEnforcePolicy(
					&tc.Policy.Spec,
				)
				Expect(err).NotTo(HaveOccurred())
				Expect(kprobespec).To(Equal(tc.Expected))
			}

		})
	})
})
