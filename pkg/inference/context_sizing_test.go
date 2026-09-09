package inference

import (
	"testing"

	"github.com/cevell/private-ai/pkg/hardware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectModelMetadataHeuristics(t *testing.T) {
	// 1. Qwen 2.5 14B
	qwen := InspectModelMetadata("Qwen/Qwen2.5-14B-Instruct")
	assert.Equal(t, 14.7, qwen.ParamCountBillions)
	assert.Contains(t, []int{32768, 131072}, qwen.ModelNativeMax)
	assert.Equal(t, 48, qwen.NumLayers)
	assert.Equal(t, 8, qwen.NumKVHeads)
	assert.False(t, qwen.IsQuantized)

	// 2. LLaMA 3.1 8B AWQ
	llama := InspectModelMetadata("meta-llama/Meta-Llama-3.1-8B-Instruct-AWQ")
	assert.Equal(t, 7.5, llama.ParamCountBillions)
	assert.Equal(t, 131072, llama.ModelNativeMax)
	assert.True(t, llama.IsQuantized)
	assert.Equal(t, 0.55, llama.BytesPerParam)

	// 3. Qwen 0.5B
	small := InspectModelMetadata("Qwen/Qwen2.5-0.5B-Instruct")
	assert.Equal(t, 0.5, small.ParamCountBillions)
	assert.Equal(t, 24, small.NumLayers)
	assert.Equal(t, 2, small.NumKVHeads)
}

func TestCalculateMaxViableContextH100(t *testing.T) {
	// NVIDIA H100 80GB HBM3
	h100Topo := hardware.TopologyReport{
		HasGPU:       true,
		GPUCount:     1,
		GPUModel:     "NVIDIA H100 80GB HBM3",
		VRAMPerGPUMB: 81920,
		VRAMTotalMB:  81920,
	}

	// 14B model on H100
	qwen14b := InspectModelMetadata("Qwen/Qwen2.5-14B-Instruct")
	maxCtx, err := CalculateMaxViableContext(qwen14b, h100Topo)
	require.NoError(t, err)
	// Weights: ~29.4GB. Usable KV budget: ~42GB.
	assert.GreaterOrEqual(t, maxCtx, 32768)
	assert.LessOrEqual(t, maxCtx, 131072)
}

func TestCalculateMaxViableContextOversizedModelRejection(t *testing.T) {
	// Tesla T4 16GB
	t4Topo := hardware.TopologyReport{
		HasGPU:       true,
		GPUCount:     1,
		GPUModel:     "Tesla T4",
		VRAMPerGPUMB: 16160,
		VRAMTotalMB:  16160,
	}

	// 70B model requires ~144GB in FP16, impossible on 16GB T4
	llama70b := InspectModelMetadata("meta-llama/Meta-Llama-3-70B-Instruct")
	_, err := CalculateMaxViableContext(llama70b, t4Topo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient GPU VRAM")
}

func TestCalculateMaxViableContextCPUMode(t *testing.T) {
	cpuTopo := hardware.TopologyReport{
		HasGPU:     false,
		GPUCount:   0,
		RAMTotalMB: 65536, // 64 GB RAM
	}

	// 0.5B model on CPU
	small := InspectModelMetadata("Qwen/Qwen2.5-0.5B-Instruct-GGUF")
	maxCtx, err := CalculateMaxViableContext(small, cpuTopo)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, maxCtx, 4096)
}

func TestAlignContextLength(t *testing.T) {
	// Tests power-of-two / standard bucket alignment
	assert.Equal(t, 32768, alignContextLength(40000, 131072))
	assert.Equal(t, 16384, alignContextLength(17000, 32768))
	assert.Equal(t, 8192, alignContextLength(10000, 8192))
	assert.Equal(t, 2048, alignContextLength(3000, 4096))
	assert.Equal(t, 1024, alignContextLength(1500, 4096))
	assert.Equal(t, 512, alignContextLength(800, 4096))
}

func TestFormatContextSize(t *testing.T) {
	assert.Equal(t, "32K", FormatContextSize(32768))
	assert.Equal(t, "8K", FormatContextSize(8192))
	assert.Equal(t, "512", FormatContextSize(512))
}

func TestCalculateMaxViableContextZeroGuards(t *testing.T) {
	// Empty/zero struct should not panic with division by zero
	zeroMeta := ModelArchitectureMeta{}
	gpuTopo := hardware.TopologyReport{
		HasGPU:       true,
		GPUCount:     1,
		GPUModel:     "Tesla T4",
		VRAMPerGPUMB: 16160,
		VRAMTotalMB:  16160,
	}
	ctx, err := CalculateMaxViableContext(zeroMeta, gpuTopo)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, ctx, 512)

	cpuTopo := hardware.TopologyReport{
		HasGPU:     false,
		GPUCount:   0,
		RAMTotalMB: 65536,
	}
	cpuCtx, err := CalculateMaxViableContext(zeroMeta, cpuTopo)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, cpuCtx, 512)
}
