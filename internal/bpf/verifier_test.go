package bpf

import (
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/testutil"
)

// run it with: go test -v -run TestNoVerifierFailures ./internal/bpf -count=1 -exec "sudo -E".
func TestNoVerifierFailures(t *testing.T) {
	tests := []struct {
		name           string
		enableLearning bool
	}{
		// We need to test both cases to be sure to catch any verifier errors
		{name: "learning disabled", enableLearning: false},
		{name: "learning enabled", enableLearning: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Loading happens here so we can catch verifier errors without running the manager
			_, err := NewManager(testutil.NewTestLogger(t), tt.enableLearning)
			if err == nil {
				t.Log("BPF manager started successfully :)!!")
				return
			}
			t.Log(err)
			t.FailNow()
		})
	}
}
