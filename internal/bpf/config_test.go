package bpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/kubewarden/runtime-enforcer/internal/testutil"
)

func TestGetHostMntNsInum(t *testing.T) {
	var st unix.Stat_t
	require.NoError(t, unix.Stat(hostInitMntNsPath, &st),
		"precondition: %s must be stat-able", hostInitMntNsPath)

	got := getHostMntNsInum(testutil.NewTestLogger(t))
	assert.Equal(t, st.Ino, got)
	assert.NotZero(t, got)
}
