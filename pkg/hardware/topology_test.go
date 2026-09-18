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

func TestClassifyArchitecture(t *testing.T) {
	tests := []struct {
		model    string
		cc       float64
		expected string
		isBW     bool
		isHopper bool
		isAda    bool
		isAmpere bool
		isTuring bool
	}{
		{"NVIDIA B200 180GB", 10.0, "Blackwell", true, false, false, false, false},
		{"NVIDIA RTX PRO 6000", 10.0, "Blackwell", true, false, false, false, false},
		{"NVIDIA H100 80GB HBM3", 9.0, "Hopper", false, true, false, false, false},
		{"NVIDIA L4", 8.9, "Ada", false, false, true, false, false},
		{"NVIDIA A100-SXM4-80GB", 8.0, "Ampere", false, false, false, true, false},
		{"Tesla T4", 7.5, "Turing", false, false, false, false, true},
	}

	for _, tc := range tests {
		report := TopologyReport{GPUModel: tc.model, ComputeCapability: tc.cc}
		classifyArchitecture(&report)
		assert.Equal(t, tc.expected, report.GPUArchitecture, "Model: %s", tc.model)
		assert.Equal(t, tc.isBW, report.IsBlackwellGPU, "Model: %s", tc.model)
		assert.Equal(t, tc.isHopper, report.IsHopperGPU, "Model: %s", tc.model)
		assert.Equal(t, tc.isAda, report.IsAdaGPU, "Model: %s", tc.model)
		assert.Equal(t, tc.isAmpere, report.IsAmpereGPU, "Model: %s", tc.model)
		assert.Equal(t, tc.isTuring, report.IsTuringGPU, "Model: %s", tc.model)
	}
}

func TestDiscoverVRAMPerGPU(t *testing.T) {
	assert.Equal(t, 184320, heuristicVRAMPerGPU("NVIDIA B200"))
	assert.Equal(t, 147456, heuristicVRAMPerGPU("NVIDIA B100"))
	assert.Equal(t, 49152, heuristicVRAMPerGPU("NVIDIA RTX PRO 6000"))
	assert.Equal(t, 81920, heuristicVRAMPerGPU("NVIDIA H100"))
	assert.Equal(t, 24576, heuristicVRAMPerGPU("NVIDIA L4"))
	assert.Equal(t, 16160, heuristicVRAMPerGPU("Tesla T4"))
}
