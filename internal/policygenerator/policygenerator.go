package policygenerator

import (
	"log/slog"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
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
	policyValuesFunc func(policyID uint64, values []string) error
}

func NewPolicyGenerator(logger *slog.Logger, informer cmCache.Informer, resolver *resolver.Resolver, policyValuesFunc func(policyID uint64, values []string) error) (*PolicyGenerator, error) {
	p := &PolicyGenerator{
		logger:           logger.With("component", "policy-informer"),
		resolver:         resolver,
		nextPolicyID:     1,
		policyValuesFunc: policyValuesFunc,
	}
	informer.AddEventHandler(p.EventHandlers())
	return p, nil
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
	logger.Debug("handler called", "method", prefix, "policy", wp.Name)
	return wp
}

func (p *PolicyGenerator) EventHandlers() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			wp := resourceCheck(p.logger, "add-policy", obj)
			if wp == nil {
				return
			}

			for containerName, containerRules := range wp.Spec.RulesByContainer {
				// we need a policy for each container rule
				policyID := p.allocPolicyID()
				if err := p.policyValuesFunc(policyID, containerRules.Executables.Allowed); err != nil {
					// todo!: it is not enough to log here, we need to populate an internal status to report the failure to the user
					p.logger.Error("failed to populate policy values", "policyID", policyID, "wp", wp.Name, "container", containerName, "error", err)
					return
				}

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
			// todo!: we do nothing for now
			// todo!: we need to handle the case of policy mode switching from monitor to enforce and viceversa
			return
		},
		DeleteFunc: func(obj interface{}) {
			// todo!: implement deletion
			return
		},
	}
}
