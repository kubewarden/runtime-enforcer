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
	logger           *slog.Logger
	resolver         *resolver.Resolver
	nextPolicyID     policyID
	policyValuesFunc func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error
	wpState          map[string]map[string]policyID
}

func SetupPolicyGenerator(logger *slog.Logger, informer cmCache.Informer, resolver *resolver.Resolver, policyValuesFunc func(policyID uint64, values []string, op bpf.PolicyValuesOperation) error) {
	p := &PolicyGenerator{
		logger:           logger.With("component", "policy-generator"),
		resolver:         resolver,
		nextPolicyID:     1,
		policyValuesFunc: policyValuesFunc,
		wpState:          make(map[string]map[string]policyID),
	}
	informer.AddEventHandler(p.EventHandlers())
}

func (p *PolicyGenerator) allocPolicyID() policyID {
	ret := p.nextPolicyID
	p.nextPolicyID++
	return ret
}

func resourceCheck(logger *slog.Logger, prefix string, obj interface{}) *securityv1alpha1.WorkloadSecurityPolicy {
	wp, ok := obj.(*securityv1alpha1.WorkloadSecurityPolicy)
	if !ok {
		logger.Error("unexpected object type", "method", prefix, "object", obj)
		return nil
	}
	logger.Info("handler called", "method", prefix, "policy-name", wp.Name, "policy-namespace", wp.Namespace)
	return wp
}

func (p *PolicyGenerator) EventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wp := resourceCheck(p.logger, "add-policy", obj)
			if wp == nil {
				return
			}
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
					// todo!: it is not enough to log here, we need to populate an internal status to report the failure to the user
					p.logger.Error("failed to add policy to resolver", "policyID", policyID, "wp", wp.Name, "container", containerName, "error", err)
					return
				}
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			// todo!: we need to handle the case of policy mode switching from monitor to enforce and viceversa and we need to handle the change of values for a specific container
			return
		},
		DeleteFunc: func(obj interface{}) {
			wp := resourceCheck(p.logger, "delete-policy", obj)
			if wp == nil {
				return
			}

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
			return
		},
	}
}
