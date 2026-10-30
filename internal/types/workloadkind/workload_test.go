package workloadkind_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/types/workloadkind"
)

func TestShortName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind workloadkind.Kind
		want string
	}{
		{workloadkind.Deployment, "deploy"},
		{workloadkind.ReplicaSet, "rs"},
		{workloadkind.DaemonSet, "ds"},
		{workloadkind.StatefulSet, "sts"},
		{workloadkind.Job, "job"},
		{workloadkind.CronJob, "cronjob"},
	}
	for _, tt := range tests {
		got, err := tt.kind.ShortName()
		require.NoError(t, err)
		assert.Equal(t, tt.want, got)
	}

	for _, kind := range []workloadkind.Kind{workloadkind.Pod, workloadkind.Unknown, "Service"} {
		_, err := kind.ShortName()
		require.ErrorContains(t, err, "unknown kind")
	}
}
