package policygenerator

import (
	"log/slog"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	cmCache "sigs.k8s.io/controller-runtime/pkg/cache"
)

const (
	policyLabelKey = "security.rancher.io/policy"
)

type policyID = uint64

type PolicyGenerator struct {
	logger               *slog.Logger
	resolver             *resolver.Resolver
	nextPolicyID         policyID
	policyValuesFunc     func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error
	policyModeUpdateFunc func(policyID uint64, mode bpf.PolicyMode) error
	wpState              map[string]map[string]policyID
}

func SetupPolicyGenerator(logger *slog.Logger, informer cmCache.Informer, resolver *resolver.Resolver, policyValuesFunc func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error, policyModeUpdateFunc func(policyID uint64, mode bpf.PolicyMode) error) {
	p := &PolicyGenerator{
		logger:               logger.With("component", "policy-generator"),
		resolver:             resolver,
		nextPolicyID:         1,
		policyValuesFunc:     policyValuesFunc,
		wpState:              make(map[string]map[string]policyID),
		policyModeUpdateFunc: policyModeUpdateFunc,
	}
	// We deliberately ignore the returned cache.ResourceEventHandlerRegistration and error here because
	// we don't need to remove the handler for the lifetime of the daemon and informer construction
	// already succeeded.
	_, _ = informer.AddEventHandler(p.EventHandlers())
}

func (p *PolicyGenerator) allocPolicyID() policyID {
	ret := p.nextPolicyID
	p.nextPolicyID++
	return ret
}

func securityPolicyToBPFMode(mode securityv1alpha1.PolicyMode) bpf.PolicyMode {
	switch mode {
	case securityv1alpha1.MonitorMode:
		return bpf.Monitor
	case securityv1alpha1.ProtectMode:
		return bpf.Protect
	default:
		panic("unhandled policy mode")
	}
}

func resourceCheck(logger *slog.Logger, prefix string, obj interface{}) *securityv1alpha1.WorkloadSecurityPolicy {
	wp, ok := obj.(*securityv1alpha1.WorkloadSecurityPolicy)
	if !ok {
		logger.Error("unexpected object type", "method", prefix, "object", obj)
		return nil
	}
	return wp
}

func (p *PolicyGenerator) EventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wp := resourceCheck(p.logger, "add-policy", obj)
			if wp == nil {
				return
			}
			p.logger.Info("handler called", "method", "add-policy", "policy-name", wp.Name, "policy-namespace", wp.Namespace)

			wpKey := wp.Namespace + "/" + wp.Name
			if _, exists := p.wpState[wpKey]; exists {
				p.logger.Error("workload policy already exists in internal state", "wp", wpKey)
				return
			}

			// we create one policy per container rule
			p.wpState[wpKey] = make(map[string]policyID, len(wp.Spec.RulesByContainer))

			for containerName, containerRules := range wp.Spec.RulesByContainer {
				// we need a policy for each container rule
				policyID := p.allocPolicyID()
				p.logger.Info("create policy", "id", policyID, "container-name", containerName)

				if err := p.policyValuesFunc(policyID, containerRules.Executables.Allowed, bpf.AddValuesToPolicy); err != nil {
					// todo!: it is not enough to log here, we need to populate an internal status to report the failure to the user
					p.logger.Error("failed to populate policy values", "policyID", policyID, "wp", wp.Name, "container", containerName, "error", err)
					return
				}

				bpfMode := securityPolicyToBPFMode(wp.Spec.Mode)
				if err := p.policyModeUpdateFunc(policyID, bpfMode); err != nil {
					p.logger.Error("failed to set policy mode", "mode", bpfMode.String(), "policyID", policyID, "wp", wp.Name, "container", containerName, "error", err)
					return
				}

				// the container name is unique per workload policy
				p.wpState[wpKey][containerName] = policyID

				containerSelector := &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "name",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{containerName},
						},
					},
				}
				podSelector := &metav1.LabelSelector{
					MatchLabels: map[string]string{
						policyLabelKey: wp.Name,
					},
				}
				if err := p.resolver.AddPolicy(policyID, wp.Namespace, podSelector, containerSelector); err != nil {
					p.logger.Error("failed to add policy to resolver", "policyID", policyID, "wp", wp.Name, "container", containerName, "error", err)
					return
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newWp := resourceCheck(p.logger, "update-policy", newObj)
			if newWp == nil {
				return
			}

			oldWp := resourceCheck(p.logger, "update-policy", oldObj)
			if oldWp == nil {
				return
			}
			p.logger.Info("handler called", "method", "update-policy", "policy-name", newWp.Name, "policy-namespace", newWp.Namespace)

			// for now we only listen to mode updates
			// todo!: we also need to handle the change of values for a specific container
			if oldWp.Spec.Mode == newWp.Spec.Mode {
				return
			}

			p.logger.Info("policy mode changed", "old-mode", oldWp.Spec.Mode, "new-mode", newWp.Spec.Mode, "wp", newWp.Name)

			wpKey := newWp.Namespace + "/" + newWp.Name
			state, exists := p.wpState[wpKey]
			if !exists {
				p.logger.Error("workload policy does not exist in internal state", "wp", wpKey)
				return
			}

			bpfMode := securityPolicyToBPFMode(newWp.Spec.Mode)
			for containerName, policyID := range state {
				if err := p.policyModeUpdateFunc(policyID, bpfMode); err != nil {
					p.logger.Error("failed to set policy mode", "mode", bpfMode.String(), "policyID", policyID, "wp", newWp.Name, "container", containerName, "error", err)
					return
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			wp := resourceCheck(p.logger, "delete-policy", obj)
			if wp == nil {
				return
			}
			p.logger.Info("handler called", "method", "delete", "policy-name", wp.Name, "policy-namespace", wp.Namespace)

			wpKey := wp.Namespace + "/" + wp.Name
			state, exists := p.wpState[wpKey]
			if !exists {
				p.logger.Error("workload policy does not exist in internal state", "wp", wpKey)
				return
			}
			delete(p.wpState, wpKey)

			for containerName, policyID := range state {
				if err := p.policyValuesFunc(policyID, []string{}, bpf.RemoveValuesFromPolicy); err != nil {
					p.logger.Error("failed to remove policy values", "policyID", policyID, "wp", wp.Name, "container", containerName, "error", err)
					return
				}
				if err := p.resolver.DeletePolicy(policyID); err != nil {
					p.logger.Error("failed to remove policy from cgroup map", "policyID", policyID, "wp", wp.Name, "container", containerName, "error", err)
					return
				}
			}
		},
	}
}
