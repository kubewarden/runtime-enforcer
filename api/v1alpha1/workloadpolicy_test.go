package v1alpha1

import (
	"testing"
	"time"

	"github.com/kubewarden/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadPolicyNamespacedName(t *testing.T) {
	wp := &WorkloadPolicy{
		Namespace: "test-namespace",
		Name:      "test-name",
	}
	expected := "test-namespace/test-name"
	require.Equal(t, expected, wp.NamespacedName())
}

func TestRecomputeStatus(t *testing.T) {
	// This test should simulate a real flow
	const (
		forgottenBinary = "/usr/bin/cat"
		containerName   = "example"
		workloadName    = "example-workload"
		workloadKind    = "Deployment"
		podA            = "pod-a"
		nodeA           = "node-a"
		podB            = "pod-b"
		nodeB           = "node-b"
	)
	baseViolation := ViolationRecord{
		ContainerName:  containerName,
		ExecutablePath: forgottenBinary,
		Action:         policymode.ProtectString,
		WorkloadName:   workloadName,
		WorkloadKind:   workloadKind,
	}
	podAViolation := baseViolation.withPodName(podA).withNodeName(nodeA)
	podBViolation := baseViolation.withPodName(podB).withNodeName(nodeB)
	baseTS := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	ts := func(sec int) time.Time {
		return baseTS.Add(time.Duration(sec) * time.Second)
	}

	policy := &WorkloadPolicy{
		Generation:  7,
		Annotations: map[string]string{},
		Spec: WorkloadPolicySpec{
			RulesByContainer: map[string]*WorkloadPolicyRules{
				containerName: {Executables: WorkloadPolicyExecutables{Allowed: []string{
					"/usr/bin/sh",
					"/usr/bin/ls",
				}}},
			},
		},
		Status: WorkloadPolicyStatus{
			ViolationCount:       0,
			ActiveViolationCount: 0,
		},
	}

	///////////////////////////
	// the user forgot a binary "/usr/bin/cat"
	///////////////////////////

	// If the application is a deployment we expect multiple violations from different nodes
	violations := []ViolationRecord{
		// The agent should send newest records first
		podAViolation.withLastObserved(ts(1)),
		podAViolation.withLastObserved(ts(2)),
		podBViolation.withLastObserved(ts(3)),
		podAViolation.withLastObserved(ts(4)),
	}

	policy.RecomputeStatus(nil, violations, ts(5))
	expectedPolicyStatus := WorkloadPolicyStatus{
		ViolationCount:       4,
		ActiveViolationCount: 2,
		Violations: []ViolationRecord{
			podAViolation.withID(0).withLastObserved(ts(4)).withOccurrences(3).withFirstObserved(ts(1)),
			// This has ID 2 because we first face 2 violation for pod-a
			podBViolation.withID(2).withLastObserved(ts(3)).withOccurrences(1).withFirstObserved(ts(3)),
		},
		ObservedGeneration: 7,
		Phase:              Ready,
	}
	require.Equal(t, expectedPolicyStatus, policy.Status)

	///////////////////////////
	// the user set the policy to monitor
	///////////////////////////

	// we should receive new violation in monitor mode so we convert them
	podAViolationMonitor := podAViolation.withAction(policymode.MonitorString)
	podBViolationMonitor := podBViolation.withAction(policymode.MonitorString)
	violations = []ViolationRecord{
		// The agent should send newest records first
		podAViolationMonitor.withLastObserved(ts(20)),
		podBViolationMonitor.withLastObserved(ts(21)),
		podAViolationMonitor.withLastObserved(ts(22)),
	}
	policy.RecomputeStatus(nil, violations, ts(24))
	expectedPolicyStatus = WorkloadPolicyStatus{
		ViolationCount:       7,
		ActiveViolationCount: 4,
		Violations: []ViolationRecord{
			podAViolationMonitor.withID(4).withLastObserved(ts(22)).withOccurrences(2).withFirstObserved(ts(20)),
			podBViolationMonitor.withID(5).withLastObserved(ts(21)).withOccurrences(1).withFirstObserved(ts(21)),
			podAViolation.withID(0).withLastObserved(ts(4)).withOccurrences(3).withFirstObserved(ts(1)),
			podBViolation.withID(2).withLastObserved(ts(3)).withOccurrences(1).withFirstObserved(ts(3)),
		},
		ObservedGeneration: 7,
		Phase:              Ready,
	}
	require.Equal(t, expectedPolicyStatus, policy.Status)

	///////////////////////////
	// the user adds the binary into the spec
	///////////////////////////

	policy.Spec.RulesByContainer[containerName].Executables.Allowed =
		append(policy.Spec.RulesByContainer[containerName].Executables.Allowed, forgottenBinary)
	policy.Generation = 8

	// Some new violations comes in the meantime
	violations = []ViolationRecord{
		podAViolationMonitor.withLastObserved(ts(40)),
		podBViolationMonitor.withLastObserved(ts(41)),
	}
	policy.RecomputeStatus(nil, violations, ts(42))
	expectedPolicyStatus = WorkloadPolicyStatus{
		ViolationCount:       9,
		ActiveViolationCount: 0,
		Violations:           []ViolationRecord{},
		ObservedGeneration:   8,
		Phase:                Ready,
	}
	require.Equal(t, expectedPolicyStatus, policy.Status)

	///////////////////////////
	// A real violation comes
	///////////////////////////

	violations = []ViolationRecord{
		podAViolation.withLastObserved(ts(100)).withExecutable("/usr/bin/malware"),
	}
	policy.RecomputeStatus(nil, violations, ts(101))
	expectedPolicyStatus = WorkloadPolicyStatus{
		ViolationCount:       10,
		ActiveViolationCount: 1,
		Violations: []ViolationRecord{
			podAViolation.withID(9).withLastObserved(ts(100)).withExecutable("/usr/bin/malware").
				withOccurrences(1).withFirstObserved(ts(100)),
		},
		ObservedGeneration: 8,
		Phase:              Ready,
	}
	require.Equal(t, expectedPolicyStatus, policy.Status)

	///////////////////////////
	// The user acknowledges it
	///////////////////////////

	policy.Annotations[ViolationAcknowledgePrefix+"9"] = "acknowledged by the user"
	acknowledgeTime := ts(120)
	policy.RecomputeStatus(nil, nil, acknowledgeTime)
	expectedPolicyStatus = WorkloadPolicyStatus{
		ViolationCount:       10,
		ActiveViolationCount: 0,
		Violations:           []ViolationRecord{},
		AcknowledgedViolations: []AcknowledgedViolationRecord{
			{
				Violation: podAViolation.withID(9).withLastObserved(ts(100)).withExecutable("/usr/bin/malware").
					withOccurrences(1).withFirstObserved(ts(100)),
				Reason:         "acknowledged by the user",
				AcknowledgedAt: metav1.Time{Time: acknowledgeTime},
			},
		},
		ObservedGeneration: 8,
		Phase:              Ready,
	}
	require.Equal(t, expectedPolicyStatus, policy.Status)
}
