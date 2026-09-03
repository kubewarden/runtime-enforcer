package kernels_test

import (
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/kernels"
	"github.com/stretchr/testify/assert"
)

func TestKernelStringToNumeric(t *testing.T) {
	v1 := kernels.KernelStringToNumeric("5.17.0")
	v2 := kernels.KernelStringToNumeric("5.17.0+")
	v3 := kernels.KernelStringToNumeric("5.17.0-foobar")
	assert.Equal(t, v1, v2)
	assert.Equal(t, v2, v3)

	v1 = kernels.KernelStringToNumeric("5.4.144+")
	v2 = kernels.KernelStringToNumeric("5.10.0")
	assert.Less(t, v1, v2)

	v1 = kernels.KernelStringToNumeric("5")
	v2 = kernels.KernelStringToNumeric("5.4")
	v3 = kernels.KernelStringToNumeric("5.4.0")
	v4 := kernels.KernelStringToNumeric("5.4.1")
	assert.Less(t, v1, v2)
	assert.Equal(t, v2, v3)
	assert.Less(t, v2, v4)

	v1 = kernels.KernelStringToNumeric("4")
	v2 = kernels.KernelStringToNumeric("4.19")
	v3 = kernels.KernelStringToNumeric("5.19")
	assert.Less(t, v1, v2)
	assert.Less(t, v2, v3)
	assert.Less(t, v1, v3)

	v1 = kernels.KernelStringToNumeric("5.4.263")
	v2 = kernels.KernelStringToNumeric("5.5.0")
	assert.Less(t, v1, v2)
}
