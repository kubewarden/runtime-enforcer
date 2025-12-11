package controller

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	WorkloadSecurityPolicyFinalizer = "workloadsecuritypolicy.security.rancher.io/finalizer"
)

type PolicyWebhook struct{}

// Default adds a finalizer to WorkloadSecurityPolicy on CREATE events.
func (w *PolicyWebhook) Default(ctx context.Context, obj runtime.Object) error {
	logger := log.FromContext(ctx)

	policy, ok := obj.(*securityv1alpha1.WorkloadSecurityPolicy)
	if !ok {
		return fmt.Errorf("expected a WorkloadSecurityPolicy but got a %T", obj)
	}

	if !controllerutil.ContainsFinalizer(policy, WorkloadSecurityPolicyFinalizer) {
		controllerutil.AddFinalizer(policy, WorkloadSecurityPolicyFinalizer)
		logger.Info("added finalizer to WorkloadSecurityPolicy", "finalizer", WorkloadSecurityPolicyFinalizer)
	}

	return nil
}
