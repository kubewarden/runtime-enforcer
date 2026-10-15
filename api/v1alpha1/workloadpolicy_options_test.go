package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionEnabled(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "one is on", value: "1", want: true},
		{name: "true is on", value: "true", want: true},
		{name: "true mixed case is on", value: "TrUe", want: true},
		{name: "true with spaces is on", value: "  true  ", want: true},
		{name: "zero is off", value: "0", want: false},
		{name: "false is off", value: "false", want: false},
		{name: "empty is off", value: "", want: false},
		{name: "other value is off", value: "yes", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, optionEnabled(tc.value))
		})
	}
}

func TestWorkloadPolicyRulesAllowForeignRootExec(t *testing.T) {
	cases := []struct {
		name    string
		options map[string]string
		want    bool
	}{
		{name: "nil options", options: nil, want: false},
		{name: "key absent", options: map[string]string{"OTHER": "1"}, want: false},
		{name: "key on", options: map[string]string{OptionAllowForeignRootExec: "1"}, want: true},
		{name: "key off", options: map[string]string{OptionAllowForeignRootExec: "0"}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := &WorkloadPolicyRules{Options: tc.options}
			assert.Equal(t, tc.want, rules.AllowForeignRootExec())
		})
	}
}

func TestUnknownOptionKeys(t *testing.T) {
	cases := []struct {
		name    string
		options map[string]string
		want    []string
	}{
		{name: "nil options", options: nil, want: nil},
		{
			name:    "known only",
			options: map[string]string{OptionAllowForeignRootExec: "1"},
			want:    nil,
		},
		{
			name:    "unknown only",
			options: map[string]string{"B_FLAG": "1", "A_FLAG": "1"},
			want:    []string{"A_FLAG", "B_FLAG"},
		},
		{
			name:    "mixed known and unknown",
			options: map[string]string{OptionAllowForeignRootExec: "1", "STALE": "1"},
			want:    []string{"STALE"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, UnknownOptionKeys(tc.options))
		})
	}
}
