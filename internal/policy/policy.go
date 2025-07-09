package policy

import (
	"fmt"
	"log/slog"
	"sync"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/pkg/generated/clientset/versioned"
	"github.com/neuvector/runtime-enforcement/pkg/generated/informers/externalversions"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type Manager struct {
	logger    *slog.Logger
	proposals map[string]*securityv1alpha1.WorkloadSecurityPolicyProposal
	lock      sync.Mutex
}

func CreatePolicyManager(logger *slog.Logger) *Manager {
	return &Manager{
		logger:    logger.With("component", "policy_manager"),
		proposals: make(map[string]*securityv1alpha1.WorkloadSecurityPolicyProposal),
	}
}

// GetWorkloadSecurityPolicyProposalName returns the name of WorkloadSecurityPolicyProposal
// based on a high level resource and its name.
func GetWorkloadSecurityPolicyProposalName(kind string, resourceName string) (string, error) {
	var shortname string
	switch kind {
	case "Deployment":
		shortname = "deploy"
	case "ReplicaSet":
		shortname = "rs"
	case "DaemonSet":
		shortname = "ds"
	case "CronJob":
		shortname = "cronjob"
	case "Job":
		shortname = "job"
	case "StatefulSet":
		shortname = "sts"
	default:
		return "", fmt.Errorf("unknown kind: %s", kind)
	}
	return shortname + "-" + resourceName, nil
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicyproposals,verbs=get;list;watch

func (pm *Manager) Start(conf *rest.Config) error {
	clientset := versioned.NewForConfigOrDie(conf)

	// Policy informer
	factory := externalversions.NewSharedInformerFactory(clientset, 0)
	_, err := factory.Security().V1alpha1().WorkloadSecurityPolicyProposals().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				pm.lock.Lock()
				defer pm.lock.Unlock()
				proposal, ok := obj.(*securityv1alpha1.WorkloadSecurityPolicyProposal)
				if !ok {
					pm.logger.Error("failed to convert to WorkloadSecurityPolicyProposal")
					return
				}

				pm.proposals[proposal.Name] = proposal
			},
			DeleteFunc: func(obj any) {
				pm.lock.Lock()
				defer pm.lock.Unlock()
				// TODO: Make sure that we have its UUID.
				proposal, ok := obj.(*securityv1alpha1.WorkloadSecurityPolicyProposal)
				if !ok {
					pm.logger.Error("failed to convert to WorkloadSecurityPolicyProposal")
					return
				}
				delete(pm.proposals, proposal.Name)
			},
			UpdateFunc: func(_ any, newObj any) {
				pm.lock.Lock()
				defer pm.lock.Unlock()
				proposal, ok := newObj.(*securityv1alpha1.WorkloadSecurityPolicyProposal)
				if !ok {
					pm.logger.Error("failed to convert to WorkloadSecurityPolicyProposal")
					return
				}
				pm.proposals[proposal.Name] = proposal
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to add workload group informer handler: %w", err)
	}
	go factory.Start(wait.NeverStop)
	return nil
}

func (pm *Manager) GetPolicy(key string) (*securityv1alpha1.WorkloadSecurityPolicyProposal, bool) {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	proposal, ok := pm.proposals[key]
	return proposal, ok
}
