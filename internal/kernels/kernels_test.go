package kernels

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestKernelStringToNumeric(t *testing.T) {
	v1 := KernelStringToNumeric("5.17.0")
	v2 := KernelStringToNumeric("5.17.0+")
	v3 := KernelStringToNumeric("5.17.0-foobar")
	assert.Equal(t, v1, v2)
	assert.Equal(t, v2, v3)

	v1 = KernelStringToNumeric("5.4.144+")
	v2 = KernelStringToNumeric("5.10.0")
	assert.Less(t, v1, v2)

	v1 = KernelStringToNumeric("5")
	v2 = KernelStringToNumeric("5.4")
	v3 = KernelStringToNumeric("5.4.0")
	v4 := KernelStringToNumeric("5.4.1")
	assert.Less(t, v1, v2)
	assert.Equal(t, v2, v3)
	assert.Less(t, v2, v4)

	v1 = KernelStringToNumeric("4")
	v2 = KernelStringToNumeric("4.19")
	v3 = KernelStringToNumeric("5.19")
	assert.Less(t, v1, v2)
	assert.Less(t, v2, v3)
	assert.Less(t, v1, v3)

	v1 = KernelStringToNumeric("5.4.263")
	v2 = KernelStringToNumeric("5.5.0")
	assert.Less(t, v1, v2)
}

func GetKernelVersion(kernelVersion, procfs string) (int, string, error) {
	var version int
	var verStr string

	if kernelVersion != "" {
		version = int(KernelStringToNumeric(kernelVersion))
		verStr = kernelVersion
	} else {
		var versionStrings []string

		if versionSig, err := os.ReadFile(procfs + "/version_signature"); err == nil {
			versionStrings = strings.Fields(string(versionSig))
		}

		if len(versionStrings) > 0 {
			version = int(KernelStringToNumeric(versionStrings[len(versionStrings)-1]))
			verStr = versionStrings[len(versionStrings)-1]
		} else {
			var uname unix.Utsname

			err := unix.Uname(&uname)
			if err != nil {
				verStr = "unknown"
				// On error default to bpf discovery which
				// will work in many cases, notable exception
				// is the cloud vendors and others that mangle
				// the kernel version string.
				return 0, verStr, nil
			}
			release := unix.ByteSliceToString(uname.Release[:])
			verStr = strings.Split(release, "-")[0]
			version = int(KernelStringToNumeric(release))
		}
	}
	return version, verStr, nil
}

func TestGetKernelVersion(t *testing.T) {
	ver, verStr, err := GetKernelVersion("", "/proc")
	require.NoError(t, err)
	assert.EqualValues(t, KernelStringToNumeric(verStr), ver)
}
