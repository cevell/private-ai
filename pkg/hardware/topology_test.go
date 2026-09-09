package hardware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscoverTopology(t *testing.T) {
	topo := DiscoverTopology()
	assert.Greater(t, topo.CPUCores, 0)
	assert.GreaterOrEqual(t, topo.RAMTotalMB, 0)
	if topo.HasGPU {
		assert.Equal(t, "vllm", topo.Recommended)
		assert.Greater(t, topo.GPUCount, 0)
		assert.NotEmpty(t, topo.GPUDevices)
	} else {
		assert.Equal(t, "gpu-required", topo.Recommended)
		assert.Equal(t, 0, topo.GPUCount)
	}
}

func TestContainsHelper(t *testing.T) {
	slice := []string{"0000:00:04.0", "0000:00:05.0"}
	assert.True(t, contains(slice, "0000:00:04.0"))
	assert.False(t, contains(slice, "0000:00:06.0"))
}
