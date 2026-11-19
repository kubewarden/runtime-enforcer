package v1alpha1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRecomputeStatusForeignRootViolations(t *testing.T) {
	for _, mode := range []string{"protect", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			rules := &WorkloadPolicyRules{
				Executables: WorkloadPolicyExecutables{Allowed: []string{"/usr/bin/true"}},
			}
			wp := &WorkloadPolicy{
				Spec: WorkloadPolicySpec{
					Mode:             mode,
					RulesByContainer: map[string]*WorkloadPolicyRules{"app": rules},
				},
			}
			local := ViolationRecord{
				PodName:               "app-pod",
				ContainerName:         "app",
				ExecutablePath:        "/usr/bin/true",
				Action:                mode,
				LastObservedTimestamp: metav1.NewTime(now),
			}
			foreign := local
			foreign.ForeignRoot = true

			// The same path denotes different violations. Only the local one
			// is resolved by the allow-list; the foreign one remains active.
			_, err := wp.RecomputeStatus(nil, []ViolationRecord{local, foreign}, now)
			require.NoError(t, err)
			require.Len(t, wp.Status.Violations, 1)
			require.True(t, wp.Status.Violations[0].ForeignRoot)
			require.Equal(t, int64(1), wp.Status.Violations[0].Occurrences)
			require.Equal(t, 1, wp.Status.ActiveViolationCount)
			foreignID := wp.Status.Violations[0].ID

			// Subsequent scrapes update the same foreign record rather than
			// dropping it and allocating a new ID each time.
			now = now.Add(time.Minute)
			foreign.LastObservedTimestamp = metav1.NewTime(now)
			_, err = wp.RecomputeStatus(nil, []ViolationRecord{foreign}, now)
			require.NoError(t, err)
			require.Len(t, wp.Status.Violations, 1)
			require.Equal(t, foreignID, wp.Status.Violations[0].ID)
			require.Equal(t, int64(2), wp.Status.Violations[0].Occurrences)
			require.Equal(t, 1, wp.Status.ActiveViolationCount)

			// The opt-out resolves foreign violations independently of the
			// allow-list, but must not resolve a now-disallowed local exec.
			rules.Executables.ForeignRoot = ForeignRootAllow
			rules.Executables.Allowed = nil
			now = now.Add(time.Minute)
			local.LastObservedTimestamp = metav1.NewTime(now)
			_, err = wp.RecomputeStatus(nil, []ViolationRecord{local}, now)
			require.NoError(t, err)
			require.Len(t, wp.Status.Violations, 1)
			require.False(t, wp.Status.Violations[0].ForeignRoot)
			require.NotEqual(t, foreignID, wp.Status.Violations[0].ID)
			require.Equal(t, 1, wp.Status.ActiveViolationCount)
		})
	}
}
