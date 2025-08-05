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
	"github.com/neuvector/runtime-enforcement/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	EventAggregatorFlushTimeout = time.Second * 10
	MaxExecutables              = 100
)

type Learner struct {
	logger          *slog.Logger
	Client          client.Client
	Cache           cache.Cache
	eventAggregator event.Aggregator
}

func CreateLearner(
	logger *slog.Logger,
	eventAggregator event.Aggregator,
) (*Learner, error) {
	var err error
	var proposalCache cache.Cache
	var proposalClient client.Client

	scheme := runtime.NewScheme()
	err = securityv1alpha1.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to add API scheme: %w", err)
	}

	proposalCache, err = cache.New(config.GetConfigOrDie(), cache.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create controller runtime cache: %w", err)
	}

	proposalClient, err = client.New(config.GetConfigOrDie(), client.Options{
		Cache: &client.CacheOptions{
			Reader: proposalCache,
		},
		Scheme: scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create controller runtime client: %w", err)
	}

	return &Learner{
		logger:          logger.With("component", "learner"),
		Cache:           proposalCache,
		Client:          proposalClient,
		eventAggregator: eventAggregator,
	}, nil
}

func (l *Learner) Start(ctx context.Context) error {
	if l.Cache != nil {
		go func() {
			if err := l.Cache.Start(ctx); err != nil {
				l.logger.ErrorContext(ctx, "failed to start cache", "error", err)
				return
			}
		}()

		if synced := l.Cache.WaitForCacheSync(ctx); !synced {
			return errors.New("cache can't be synced")
		}
	}

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
	// Send all the information we have for operator to fill in others.
	if len(policyProposal.OwnerReferences) == 0 && policyProposal.Spec.Selector == nil {
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

	logger := l.logger.With("namespace", processEvent.Namespace, "executable", processEvent.ExecutablePath)

	proposalName, err = policy.GetWorkloadSecurityPolicyProposalName(processEvent.WorkloadKind, processEvent.Workload)
	if err != nil {
		logger.ErrorContext(ctx, "failed to get proposal name", "error", err)
		return err
	}

	logger = logger.With("proposal", proposalName)

	logger.InfoContext(ctx, "handling process event")

	policyProposal := &securityv1alpha1.WorkloadSecurityPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proposalName,
			Namespace: processEvent.Namespace,
		},
	}

	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		if _, err = controllerutil.CreateOrUpdate(ctx, l.Client, policyProposal, func() error {
			return l.mutateProposal(policyProposal, processEvent)
		}); err != nil {
			return fmt.Errorf("failed to run CreateOrUpdate: %w", err)
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
