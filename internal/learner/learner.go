package learner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	securityv1alpha1 "github.com/neuvector/runtime-enforcement/api/v1alpha1"
	"github.com/neuvector/runtime-enforcement/internal/event"
	"github.com/neuvector/runtime-enforcement/internal/policy"
	"github.com/neuvector/runtime-enforcement/pkg/generated/clientset/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

const (
	EventAggregatorFlushTimeout = time.Second * 10
)

type Learner struct {
	logger          *slog.Logger
	client          *versioned.Clientset
	eventAggregator event.Aggregator
	policyMgr       *policy.Manager
}

func CreateLearner(
	logger *slog.Logger,
	conf *rest.Config,
	eventAggregator event.Aggregator,
	policyMgr *policy.Manager,
) *Learner {
	return &Learner{
		logger:          logger.With("component", "learner"),
		client:          versioned.NewForConfigOrDie(conf),
		eventAggregator: eventAggregator,
		policyMgr:       policyMgr,
	}
}

func (l *Learner) Start(ctx context.Context) error {
	go func() {
		if err := l.LearnLoop(ctx); err != nil {
			l.logger.Error("LearnLoop failed", "error", err)
		}
	}()
	return nil
}

func (l *Learner) learn(ae event.AggregatableEvent) error {
	var err error
	var pg *securityv1alpha1.WorkloadSecurityPolicyProposal
	var proposalName string

	// TODO: Rethink the interface.
	proposalName, err = ae.GetProposalName()
	if err != nil {
		return fmt.Errorf("no group ID is associated with this event: %w", err)
	}

	l.logger.Debug("the proposal is found", "proposal", proposalName)

	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		proposalClient := l.client.SecurityV1alpha1().WorkloadSecurityPolicyProposals(ae.GetNamespace())
		pg, err = proposalClient.Get(context.TODO(), proposalName, v1.GetOptions{})
		if err != nil {
			return err
		}
		pg.Spec.Rules.Executables.Allowed = append(pg.Spec.Rules.Executables.Allowed, ae.GetExecutablePath())

		dedup := map[string]bool{}
		for _, v := range pg.Spec.Rules.Executables.Allowed {
			dedup[v] = true
		}

		pg.Spec.Rules.Executables.Allowed = nil

		for k := range dedup {
			pg.Spec.Rules.Executables.Allowed = append(pg.Spec.Rules.Executables.Allowed, k)
		}

		_, err = proposalClient.Update(context.TODO(), pg, v1.UpdateOptions{})
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to update security policy proposal with %s: %w", ae.GetExecutablePath(), err)
	}

	return nil
}

//nolint:lll // kubebuilder markers
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadsecuritypolicyproposals,verbs=get;list;watch;update;patch

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

			l.logger.Info("Getting events", "event", string(eb))

			if err = l.learn(ae); err != nil {
				return true, fmt.Errorf("failed to learn process: %w", err)
			}
			return true, nil
		}); err != nil {
			l.logger.ErrorContext(ctx, "failed to flush event", "error", err)
		}
	}
}
