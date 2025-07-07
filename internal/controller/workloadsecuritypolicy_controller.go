package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	tetragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// UpdateTetragonPolicy updates a tetragon policy based on WorkloadSecurityPolicy.
func UpdateTetragonPolicy(
	spec *securityv1alpha1.WorkloadSecurityPolicySpec,
	tetragonSpec *tetragonv1alpha1.TracingPolicySpec,
) error {
	// KProbe only for now
	kprobe, err := GenerateKProbeEnforcePolicy(spec)
	if err != nil {
		return fmt.Errorf("failed to generate kprobe enforce policy: %w", err)
	}

	kprobe.Tags = spec.Tags
	kprobe.Message = fmt.Sprintf("[%d] %s", spec.Severity, spec.Message)

	tetragonSpec.KProbes = []tetragonv1alpha1.KProbeSpec{
		kprobe,
	}
	tetragonSpec.Options = []tetragonv1alpha1.OptionSpec{
		{
			Name:  "disable-kprobe-multi",
			Value: "1",
		},
	}

	// Append pod selector
	if spec.Selector != nil {
		tetragonSpec.PodSelector = &slimv1.LabelSelector{
			MatchLabels:      spec.Selector.MatchLabels,
			MatchExpressions: ConvertMatchExpressions(spec.Selector.MatchExpressions),
		}
	}

	return nil
}

func ConvertMatchExpressions(
	matchExpressions []metav1.LabelSelectorRequirement,
) []slimv1.LabelSelectorRequirement {
	var ret []slimv1.LabelSelectorRequirement
	for _, labelSelectorRequirement := range matchExpressions {
		ret = append(ret, slimv1.LabelSelectorRequirement{
			Key:      labelSelectorRequirement.Key,
			Operator: slimv1.LabelSelectorOperator(labelSelectorRequirement.Operator),
			Values:   labelSelectorRequirement.Values,
		})
	}
	return ret
}

// GenerateKProbeEnforcePolicy creates a tetragon KprobeSpec based workload security policy.
func GenerateKProbeEnforcePolicy(
	spec *securityv1alpha1.WorkloadSecurityPolicySpec,
) (tetragonv1alpha1.KProbeSpec, error) {
	ret := tetragonv1alpha1.KProbeSpec{
		Call:    "security_bprm_creds_for_exec",
		Syscall: false,
		Args: []tetragonv1alpha1.KProbeArg{
			{
				Index: 0,
				Type:  "linux_binprm",
			},
		},
		Selectors: []tetragonv1alpha1.KProbeSelector{},
	}

	var kprobeSelector tetragonv1alpha1.KProbeSelector

	if securityv1alpha1.PolicyMode(spec.Mode) == securityv1alpha1.ProtectMode {
		kprobeSelector.MatchActions = []tetragonv1alpha1.ActionSelector{
			{
				Action:   "Override",
				ArgError: -1,
			},
		}
	}

	if len(spec.Rules.Executables.Allowed) > 0 {
		kprobeSelector.MatchArgs = append(kprobeSelector.MatchArgs, tetragonv1alpha1.ArgSelector{
			Index:    0,
			Operator: "NotEqual",
			Values:   spec.Rules.Executables.Allowed,
		})
	}
	if len(spec.Rules.Executables.AllowedPrefixes) > 0 {
		kprobeSelector.MatchArgs = append(kprobeSelector.MatchArgs, tetragonv1alpha1.ArgSelector{
			Index:    0,
			Operator: "NotPrefix",
			Values:   spec.Rules.Executables.AllowedPrefixes,
		})
	}

	ret.Selectors = append(ret.Selectors, kprobeSelector)

	return ret, nil
}

// WorkloadSecurityPolicyReconciler reconciles a WorkloadSecurityPolicy object.
type WorkloadSecurityPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//nolint:lll // kubebuilder markers
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=cilium.io,resources=tracingpoliciesnamespaced,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cilium.io,resources=tracingpolicies,verbs=get;list;watch;create;update;patch;delete

//nolint:dupl // we're more tolerant with controller code.
func (r *WorkloadSecurityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("workloadsecuritypolicy", "req", req)

	var policy securityv1alpha1.WorkloadSecurityPolicy
	var err error
	if err = r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var tetragonPolicy tetragonv1alpha1.TracingPolicyNamespaced
	tetragonPolicy.Name = policy.Name
	tetragonPolicy.Namespace = policy.Namespace
	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		_, err = controllerutil.CreateOrUpdate(ctx, r.Client, &tetragonPolicy, func() error {
			err = UpdateTetragonPolicy(&policy.Spec, &tetragonPolicy.Spec)
			if err != nil {
				return fmt.Errorf("failed to update Tetragon Policy: %w", err)
			}
			err = controllerutil.SetControllerReference(&policy, &tetragonPolicy, r.Scheme)
			if err != nil {
				return fmt.Errorf("failed to set controller reference: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to call CreateOrUpdate: %w", err)
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, r.reportError(ctx, &policy, err)
	}

	return ctrl.Result{}, r.updateStatus(ctx, &policy)
}

func (r *WorkloadSecurityPolicyReconciler) updateStatus(
	ctx context.Context,
	policy *securityv1alpha1.WorkloadSecurityPolicy,
) error {
	newPolicy := policy.DeepCopy()
	newPolicy.Status.ObservedGeneration = newPolicy.Generation
	newPolicy.Status.State = securityv1alpha1.DeployedState
	return r.Status().Update(ctx, newPolicy)
}

func (r *WorkloadSecurityPolicyReconciler) reportError(
	ctx context.Context,
	policy *securityv1alpha1.WorkloadSecurityPolicy,
	err error,
) error {
	newPolicy := policy.DeepCopy()
	if newPolicy.Status.Conditions == nil {
		newPolicy.Status.Conditions = make([]metav1.Condition, 0)
	}
	apimeta.SetStatusCondition(&newPolicy.Status.Conditions, metav1.Condition{
		Type:               securityv1alpha1.DeployCondition,
		Status:             metav1.ConditionFalse,
		Reason:             securityv1alpha1.SyncFailedReason,
		Message:            err.Error(),
		ObservedGeneration: newPolicy.Status.ObservedGeneration,
	})
	newPolicy.Status.State = securityv1alpha1.ErrorState
	newPolicy.Status.Reason = err.Error()
	return r.Status().Update(ctx, newPolicy)
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadSecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := tetragonv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadSecurityPolicy{}).
		Named("workloadsecuritypolicy").
		Complete(r)
}
