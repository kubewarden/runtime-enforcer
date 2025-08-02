package learner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/event"
	"github.com/neuvector/runtime-enforcement/pkg/generated/clientset/versioned"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

const (
	EventAggregatorFlushTimeout = time.Second * 10
	MaxExecutables              = 100
)

type Learner struct {
	logger          *slog.Logger
	client          *versioned.Clientset
	eventAggregator event.Aggregator
}

func CreateLearner(
	logger *slog.Logger,
	conf *rest.Config,
	eventAggregator event.Aggregator,
) *Learner {
	return &Learner{
		logger:          logger.With("component", "learner"),
		client:          versioned.NewForConfigOrDie(conf),
		eventAggregator: eventAggregator,
	}
}

func (l *Learner) Start(ctx context.Context) error {
	go func() {
		if err := l.LearnLoop(ctx); err != nil {
			l.logger.ErrorContext(ctx, "LearnLoop failed", "error", err)
		}
	}()
	return nil
}

// addProcessToProposal adds a process into the policy proposal.
func (l *Learner) addProcessToProposal(
	obj *securityv1alpha1.WorkloadSecurityPolicyProposal,
	processEvent *event.ProcessEvent,
) error {
	if len(obj.Spec.Rules.Executables.Allowed) >= MaxExecutables {
		return errors.New("the number of executables has exceeded its maximum")
	}
	if slices.Contains(obj.Spec.Rules.Executables.Allowed, processEvent.ExecutablePath) {
		return nil
	}

	obj.Spec.Rules.Executables.Allowed = append(obj.Spec.Rules.Executables.Allowed, processEvent.ExecutablePath)

	return nil
}

func (l *Learner) mutateProposal(
	policyProposal *securityv1alpha1.WorkloadSecurityPolicyProposal,
	processEvent *event.ProcessEvent,
) error {
	if len(policyProposal.OwnerReferences) == 0 {
		policyProposal.OwnerReferences = []metav1.OwnerReference{
			{
				Kind: processEvent.WorkloadKind,
				Name: processEvent.Workload,
			},
		}
	}

	err := l.addProcessToProposal(policyProposal, processEvent)
	if err != nil {
		return fmt.Errorf("failed to mutate proposal: %w", err)
	}

	return nil
}

func (l *Learner) learn(ctx context.Context, ae event.AggregatableEvent) error {
	var err error
	var proposalName string

	processEvent, ok := ae.(*event.ProcessEvent)
	if !ok {
		return errors.New("unknown type: %T, expected: ProcessEvent")
	}

	// TODO: Rethink the interface.
	proposalName, err = processEvent.GetProposalName()
	if err != nil {
		return fmt.Errorf("no group ID is associated with this event: %w", err)
	}

	l.logger.DebugContext(ctx, "the proposal is found", "proposal", proposalName)

	policyProposal := &securityv1alpha1.WorkloadSecurityPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proposalName,
			Namespace: processEvent.Namespace,
		},
	}

	// Here implements a GetOrUpdate.
	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var proposal *securityv1alpha1.WorkloadSecurityPolicyProposal
		proposalClient := l.client.SecurityV1alpha1().WorkloadSecurityPolicyProposals(ae.GetNamespace())
		if proposal, err = proposalClient.Get(ctx, proposalName, metav1.GetOptions{}); err != nil {
			if !k8sErrors.IsNotFound(err) {
				return fmt.Errorf("failed to get proposal: %w", err)
			}

			if err = l.mutateProposal(policyProposal, processEvent); err != nil {
				return err
			}

			_, err = proposalClient.Create(ctx, policyProposal, metav1.CreateOptions{})
			if err != nil {
				return err
			}
			return nil
		}

		if err = l.mutateProposal(proposal, processEvent); err != nil {
			return err
		}

		_, err = proposalClient.Update(ctx, proposal, metav1.UpdateOptions{})
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to update security policy proposal with %s: %w", ae.GetExecutablePath(), err)
	}

	return nil
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicyproposals,verbs=create;get;list;watch;update;patch

func (l *Learner) LearnLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("learner loop has completed: %w", ctx.Err())
		default:
		}
		// TODO: Do not hardcode it
		time.Sleep(EventAggregatorFlushTimeout)
		if err := l.eventAggregator.Flush(func(ae event.AggregatableEvent) (bool, error) {
			eb, err := json.Marshal(ae)
			if err != nil {
				return true, fmt.Errorf("failed to marshal event: %w", err)
			}

			l.logger.InfoContext(ctx, "Getting events", "event", string(eb))

			if err = l.learn(ctx, ae); err != nil {
				return true, fmt.Errorf("failed to learn process: %w", err)
			}
			return true, nil
		}); err != nil {
			l.logger.ErrorContext(ctx, "failed to flush event", "error", err)
		}
	}
}
