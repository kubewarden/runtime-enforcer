package kernels

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func KernelStringToNumeric(ver string) int64 {
	// vendors like to define kernel 4.14.128-foo but
	// everything after '-' is meaningless from BPF
	// side so toss it out.
	release := strings.Split(ver, "-")
	verStr := release[0]
	numeric := strings.TrimRight(verStr, "+")
	vers := strings.Split(numeric, ".")

	const (
		kernelVersionPatchMax   = 255
		kernelVersionMajorShift = 16
		kernelVersionMinorShift = 8
	)

	// Split out major, minor, and patch versions
	majorS := vers[0]
	minorS := ""
	if len(vers) >= 2 { //nolint:mnd // minor version is optional
		minorS = vers[1]
	}
	patchS := ""
	if len(vers) >= 3 { //nolint:mnd // patch version is optional
		patchS = vers[2]
	}

	// If we have no major version number, all is lost
	major, err := strconv.ParseInt(majorS, 10, 32)
	if err != nil {
		return 0
	}
	// Fall back to minor = 0 if we can't parse the minor version
	minor, err := strconv.ParseInt(minorS, 10, 32)
	if err != nil {
		minor = 0
	}
	// Fall back to patch = 0 if we can't parse the patch version
	patch, err := strconv.ParseInt(patchS, 10, 32)
	if err != nil {
		patch = 0
	}
	// Similar to https://elixir.bootlin.com/linux/v6.2.16/source/tools/lib/bpf/bpf_helpers.h#L74
	// we have to check that patch is <= 255. Otherwise make that 255.
	if patch > kernelVersionPatchMax {
		patch = kernelVersionPatchMax
	}

	return ((major << kernelVersionMajorShift) + (minor << kernelVersionMinorShift) + patch)
}

func MinKernelVersion(kernel string) bool {
	var uname unix.Utsname

	if err := unix.Uname(&uname); err != nil {
		return true
	}
	// vendors like to define kernel 4.14.128-foo but
	// everything after '-' is meaningless from BPF
	// side so toss it out.
	release := strings.TrimSuffix(
		strings.Split(unix.ByteSliceToString(uname.Release[:]), "-")[0],
		"+")

	runningVersion := int(KernelStringToNumeric(release))
	minVersion := int(KernelStringToNumeric(kernel))

	return minVersion <= runningVersion
}
