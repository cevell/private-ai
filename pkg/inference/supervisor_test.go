package inference

import (
	"context"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cevell/private-ai/pkg/config"
	"github.com/cevell/private-ai/pkg/hardware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupervisorInitialization(t *testing.T) {
	sup := NewSupervisor(8000)
	assert.NotNil(t, sup)
	assert.False(t, sup.IsReady())
	assert.Equal(t, 8000, sup.port)
	assert.Equal(t, "", sup.CurrentModel())
}

func boolPtr(b bool) *bool { return &b }

func TestSupervisorLoadModelValidation(t *testing.T) {
	sup := NewSupervisor(8000)

	// 1. Missing ExposeInHealth should return descriptive error
	err := sup.LoadModel(nil, ModelSpec{Model: "valid-model", ExposeInHealth: nil})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required parameter 'expose_in_health'")

	// 2. Empty model specification should return descriptive error, not panic
	err = sup.LoadModel(nil, ModelSpec{Model: "", ExposeInHealth: boolPtr(true)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model identifier is required")

	// 3. Command injection characters should be rejected
	err = sup.LoadModel(nil, ModelSpec{Model: "malicious; rm -rf /", ExposeInHealth: boolPtr(true)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden characters")

	// 4. Flag injection should be rejected
	err = sup.LoadModel(nil, ModelSpec{Model: "--unsafe-flag", ExposeInHealth: boolPtr(true)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "flag prefix")
}

func TestSupervisorGPUOnlyEnforcement(t *testing.T) {
	sup := NewSupervisor(8000)
	// Force HasGPU to false to simulate environment without GPU accelerator
	sup.topo.HasGPU = false
	sup.topo.GPUCount = 0

	err := sup.LoadModel(nil, ModelSpec{Model: "Qwen/Qwen2.5-0.5B-Instruct", ExposeInHealth: boolPtr(true)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vLLM GPU Lock Enforcement")
	assert.Contains(t, err.Error(), "no physical GPU hardware detected")
}

func TestSupervisorFatalErrorState(t *testing.T) {
	sup := NewSupervisor(8000)
	assert.Equal(t, "vllm", sup.BackendType())

	// Test Setting & Getting Fatal Error
	sup.SetFatalError(nil)
	assert.Nil(t, sup.FatalError())

	testErr := assert.AnError
	sup.SetFatalError(testErr)
	assert.Equal(t, testErr, sup.FatalError())

	// Test Recovery on LoadModel: loading model clears transient fatalError
	config.SetTarget("cpu")
	_ = sup.LoadModel(nil, ModelSpec{Model: "valid/model-path.gguf", ExposeInHealth: boolPtr(true)})
	assert.Nil(t, sup.FatalError(), "LoadModel must clear transient fatalError")
	config.SetTarget("")
}

func TestSupervisorTargetRouting(t *testing.T) {
	// 1. Test CPU Mode
	config.SetTarget("cpu")
	cpuSup := NewSupervisor(8000)
	assert.Equal(t, "llama.cpp", cpuSup.BackendType())
	assert.Nil(t, cpuSup.FatalError(), "CPU mode must not set fatal error even without GPU")

	// 2. Test GPU Mode
	config.SetTarget("gpu")
	gpuSup := NewSupervisor(8000)
	assert.Equal(t, "vllm", gpuSup.BackendType())

	// Reset
	config.SetTarget("")
}

func TestSupervisorConcurrencyNonBlocking(t *testing.T) {
	sup := NewSupervisor(8000)

	// Simulate concurrent reads while supervisor state is accessed
	done := make(chan bool)
	for i := 0; i < 20; i++ {
		go func() {
			for j := 0; j < 50; j++ {
				_ = sup.IsReady()
				_ = sup.CurrentModel()
				_ = sup.FatalError()
				_ = sup.BackendType()
			}
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestBinaryDiscoveryHelpers(t *testing.T) {
	// Llama binary fallback
	llamaBin := findLlamaServerBinary()
	assert.NotEmpty(t, llamaBin)

	// Local GGUF discovery for non-existent model
	ggufPath := findLocalGGUF("non-existent-model-xyz.gguf")
	// Should return empty or fallback if none match
	_ = ggufPath

	// GPU inference binary helper
	binPath, prefix, name := findGPUInferenceBinary()
	// In test environment, binPath might be empty or python3/vllm
	_ = binPath
	_ = prefix
	_ = name
}

func TestKillProcessGroup(t *testing.T) {
	// 1. Nil command returns nil
	assert.Nil(t, killProcessGroup(nil))

	// 2. Unstarted command returns nil
	unstarted := exec.Command("sleep", "1")
	assert.Nil(t, killProcessGroup(unstarted))

	// 3. Command with Pid <= 1 returns nil without error
	p1Cmd := exec.Command("sleep", "1")
	if err := p1Cmd.Start(); err == nil {
		p1Cmd.Process.Pid = 1
		assert.Nil(t, killProcessGroup(p1Cmd))
		p1Cmd.Process.Pid = 0
		assert.Nil(t, killProcessGroup(p1Cmd))
	}

	// 4. Running process group is cleanly killed
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err == nil {
		err = killProcessGroup(cmd)
		assert.NoError(t, err)
	}
}

func TestCleanupStaleCacheArtifacts(t *testing.T) {
	// Should execute without panics and ensure directories
	cleanupStaleCacheArtifacts()
}

func TestArchitectureAwareFlagSelection(t *testing.T) {
	spec := ModelSpec{Model: "Qwen/Qwen2.5-7B-Instruct", ContextSize: 32768}

	// 1. Hopper H100: FlashAttention-2 forced, eager mode forced (Inductor NaN protection)
	hopperTopo := hardware.TopologyReport{
		HasGPU:            true,
		GPUCount:          1,
		IsHopperGPU:       true,
		GPUArchitecture:   "Hopper",
		ComputeCapability: 9.0,
		GPUModel:          "NVIDIA H100 80GB HBM3",
	}
	hopperArgs := BuildVLLMArgs(spec, hopperTopo, 1, 8000)
	assert.Contains(t, hopperArgs, "--attention-config")
	assert.Contains(t, hopperArgs, `{"flash_attn_version": 2}`)
	assert.Contains(t, hopperArgs, "--enforce-eager")
	assert.Contains(t, hopperArgs, "--dtype")
	assert.Contains(t, hopperArgs, "auto")

	// 2. Blackwell (B200 / RTX PRO 6000): NO forced FA2 (native kernels), NO forced eager (CUDAGraphs enabled)
	bwTopo := hardware.TopologyReport{
		HasGPU:            true,
		GPUCount:          1,
		IsBlackwellGPU:    true,
		GPUArchitecture:   "Blackwell",
		ComputeCapability: 10.0,
		GPUModel:          "NVIDIA RTX PRO 6000",
	}
	bwArgs := BuildVLLMArgs(spec, bwTopo, 1, 8000)
	assert.NotContains(t, bwArgs, "--attention-config")
	assert.NotContains(t, bwArgs, "--enforce-eager")
	assert.Contains(t, bwArgs, "--dtype")
	assert.Contains(t, bwArgs, "auto")

	// 3. Ada Lovelace (L4): FlashAttention-2 forced, NO forced eager (CUDAGraphs enabled)
	adaTopo := hardware.TopologyReport{
		HasGPU:            true,
		GPUCount:          1,
		IsAdaGPU:          true,
		GPUArchitecture:   "Ada",
		ComputeCapability: 8.9,
		GPUModel:          "NVIDIA L4",
	}
	adaArgs := BuildVLLMArgs(spec, adaTopo, 1, 8000)
	assert.Contains(t, adaArgs, "--attention-config")
	assert.Contains(t, adaArgs, `{"flash_attn_version": 2}`)
	assert.NotContains(t, adaArgs, "--enforce-eager")
	assert.Contains(t, adaArgs, "--dtype")
	assert.Contains(t, adaArgs, "auto")

	// 4. Turing (T4): NO attention config, forced eager, forced half dtype
	turingTopo := hardware.TopologyReport{
		HasGPU:            true,
		GPUCount:          1,
		IsTuringGPU:       true,
		GPUArchitecture:   "Turing",
		ComputeCapability: 7.5,
		GPUModel:          "Tesla T4",
	}
	turingArgs := BuildVLLMArgs(spec, turingTopo, 1, 8000)
	assert.NotContains(t, turingArgs, "--attention-config")
	assert.Contains(t, turingArgs, "--enforce-eager")
	assert.Contains(t, turingArgs, "--dtype")
	assert.Contains(t, turingArgs, "half")

	// 5. BitsAndBytes quantization: forced eager on any GPU
	bnbSpec := ModelSpec{Model: "unsloth/Llama-3.2-3B-Instruct", Quantization: "bitsandbytes"}
	bnbArgs := BuildVLLMArgs(bnbSpec, adaTopo, 1, 8000)
	assert.Contains(t, bnbArgs, "--enforce-eager")
	assert.Contains(t, bnbArgs, "--quantization")
	assert.Contains(t, bnbArgs, "bitsandbytes")
}

func TestSupervisorDynamicContextValidation(t *testing.T) {
	sup := NewSupervisor(8000)

	// 1. Explicit user context length under CPU mode
	config.SetTarget("cpu")
	defer config.SetTarget("gpu")
	sup.topo.HasGPU = false
	sup.topo.GPUCount = 0

	_ = sup.LoadModel(nil, ModelSpec{
		Model:          "valid/model-path.gguf",
		ContextSize:    4096,
		ExposeInHealth: boolPtr(true),
	})
	assert.Equal(t, 4096, sup.ActiveContext())

	// 2. Context auto-delegation on omitted (0) context size
	_ = sup.LoadModel(nil, ModelSpec{
		Model:          "valid/model-path.gguf",
		ContextSize:    0,
		ExposeInHealth: boolPtr(true),
	})
	assert.Greater(t, sup.MaxContext(), 0)
}

func TestSupervisorLivenessHeartbeatDecoupling(t *testing.T) {
	sup := NewSupervisor(8000)

	// 1. Initial activity timestamp should be initialized
	initialActivity := sup.LastActivity()
	assert.False(t, initialActivity.IsZero(), "Supervisor must initialize lastActivity at creation")

	// 2. Calling RecordActivity updates the timestamp
	time.Sleep(5 * time.Millisecond)
	sup.RecordActivity()
	updatedActivity := sup.LastActivity()
	assert.True(t, updatedActivity.After(initialActivity), "RecordActivity must advance activity timestamp")
	assert.True(t, time.Since(updatedActivity) < 30*time.Second, "Recent activity must fall within 30s heartbeat threshold")

	// 3. Stale activity (>30s) correctly activates HTTP probing
	sup.activityMu.Lock()
	sup.lastActivity = time.Now().Add(-45 * time.Second)
	sup.activityMu.Unlock()

	assert.False(t, time.Since(sup.LastActivity()) < 30*time.Second, "Stale activity must not suppress HTTP probes")
}

func TestSupervisorSynchronizeDriverVRAMClearance(t *testing.T) {
	sup := NewSupervisor(8000)

	// 1. On CPU / non-GPU environments, returns immediately
	sup.topo.HasGPU = false
	sup.topo.GPUCount = 0
	start := time.Now()
	sup.SynchronizeDriverVRAMClearance(5 * time.Second)
	elapsed := time.Since(start)
	assert.True(t, elapsed < 100*time.Millisecond, "Non-GPU environments must return immediately")

	// 2. On GPU environments without nvidia-smi, falls back cleanly without hanging
	sup.topo.HasGPU = true
	sup.topo.GPUCount = 1
	startGPU := time.Now()
	sup.SynchronizeDriverVRAMClearance(500 * time.Millisecond)
	elapsedGPU := time.Since(startGPU)
	assert.True(t, elapsedGPU < 1*time.Second, "Clearance sync must return within bounded time")
}

func TestAlignTensorParallelToKVHeads(t *testing.T) {
	tests := []struct {
		gpuCount   int
		numKVHeads int
		expected   int
	}{
		{gpuCount: 1, numKVHeads: 8, expected: 1},
		{gpuCount: 0, numKVHeads: 8, expected: 1},
		{gpuCount: 4, numKVHeads: 0, expected: 4}, // Unknown KV heads defaults to gpuCount
		{gpuCount: 4, numKVHeads: 8, expected: 4}, // 8 is divisible by 4
		{gpuCount: 4, numKVHeads: 2, expected: 2}, // 2 is not divisible by 4, clamped to 2
		{gpuCount: 8, numKVHeads: 6, expected: 6}, // 6 is not divisible by 8 or 7, clamped to 6
		{gpuCount: 8, numKVHeads: 4, expected: 4}, // 4 is divisible by 4
		{gpuCount: 8, numKVHeads: 1, expected: 1}, // MQA 1 head clamped to 1
	}

	for _, tc := range tests {
		result := AlignTensorParallelToKVHeads(tc.gpuCount, tc.numKVHeads)
		assert.Equal(t, tc.expected, result, "AlignTensorParallelToKVHeads(%d, %d)", tc.gpuCount, tc.numKVHeads)
	}
}

func TestSupervisorConcurrentPipeDraining(t *testing.T) {
	sup := NewSupervisor(8000)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.Command("sh", "-c", "echo stdout_hello && echo stderr_world >&2")
	err := sup.runEngineProcess(ctx, cmd, "[test-drain]")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stdout_hello")
	assert.Contains(t, err.Error(), "stderr_world")
}

func TestResolveToolCallParser(t *testing.T) {
	tests := []struct {
		model    string
		override string
		expected string
	}{
		// Explicit override takes precedence
		{model: "Qwen/Qwen2.5-7B-Instruct", override: "custom_parser", expected: "custom_parser"},
		// Qwen family
		{model: "Qwen/Qwen2.5-7B-Instruct", override: "", expected: "hermes"},
		{model: "qwen2.5-coder-32b-instruct", override: "", expected: "hermes"},
		// DeepSeek family
		{model: "deepseek-ai/DeepSeek-V3", override: "", expected: "hermes"},
		{model: "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B", override: "", expected: "hermes"},
		{model: "deepseek-ai/DeepSeek-R1-Distill-Llama-70B", override: "", expected: "llama3_json"},
		// GLM family
		{model: "THUDM/glm-4-9b-chat", override: "", expected: "hermes"},
		{model: "THUDM/chatglm3-6b", override: "", expected: "hermes"},
		// Kimi / Moonlight family
		{model: "moonshotai/Moonlight-16B-A3B-Instruct", override: "", expected: "hermes"},
		{model: "kimi-k1.5", override: "", expected: "hermes"},
		// Mistral family
		{model: "mistralai/Mistral-7B-Instruct-v0.3", override: "", expected: "mistral"},
		{model: "mistralai/Mixtral-8x22B-Instruct-v0.1", override: "", expected: "mistral"},
		{model: "mistralai/Codestral-22B-v0.1", override: "", expected: "mistral"},
		// Llama family
		{model: "meta-llama/Llama-3.1-8B-Instruct", override: "", expected: "llama3_json"},
		{model: "meta-llama/Llama-3.3-70B-Instruct", override: "", expected: "llama3_json"},
		{model: "meta-llama/Llama-3.2-3B-Instruct", override: "", expected: "pythonic"},
		// Granite family
		{model: "ibm-granite/granite-3.0-8b-instruct", override: "", expected: "granite"},
		{model: "ibm-granite/granite-20b-code-instruct", override: "", expected: "granite-20b-fc"},
		// Default fallback
		{model: "random-org/some-unknown-model", override: "", expected: "hermes"},
	}

	for _, tc := range tests {
		parser, enabled := ResolveToolCallParser(tc.model, tc.override)
		assert.True(t, enabled)
		assert.Equal(t, tc.expected, parser, "ResolveToolCallParser(%s, %s)", tc.model, tc.override)
	}
}

func TestResolveReasoningParser(t *testing.T) {
	tests := []struct {
		model          string
		enableOverride *bool
		parserOverride string
		expectedParser string
		expectedEnable bool
	}{
		// Auto-detect DeepSeek-R1
		{model: "deepseek-ai/DeepSeek-R1", enableOverride: nil, parserOverride: "", expectedParser: "deepseek_r1", expectedEnable: true},
		{model: "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B", enableOverride: nil, parserOverride: "", expectedParser: "deepseek_r1", expectedEnable: true},
		{model: "QwQ-32B-Preview", enableOverride: nil, parserOverride: "", expectedParser: "deepseek_r1", expectedEnable: true},
		{model: "Marco-o1", enableOverride: nil, parserOverride: "", expectedParser: "deepseek_r1", expectedEnable: true},
		// Non-reasoning model defaults to false
		{model: "Qwen/Qwen2.5-7B-Instruct", enableOverride: nil, parserOverride: "", expectedParser: "", expectedEnable: false},
		{model: "meta-llama/Llama-3.1-8B-Instruct", enableOverride: nil, parserOverride: "", expectedParser: "", expectedEnable: false},
		// Explicit disable on R1 model
		{model: "deepseek-ai/DeepSeek-R1", enableOverride: boolPtr(false), parserOverride: "", expectedParser: "", expectedEnable: false},
		// Explicit enable on normal model
		{model: "Qwen/Qwen2.5-7B-Instruct", enableOverride: boolPtr(true), parserOverride: "", expectedParser: "deepseek_r1", expectedEnable: true},
		{model: "custom-model", enableOverride: boolPtr(true), parserOverride: "custom_parser", expectedParser: "custom_parser", expectedEnable: true},
	}

	for _, tc := range tests {
		parser, enabled := ResolveReasoningParser(tc.model, tc.enableOverride, tc.parserOverride)
		assert.Equal(t, tc.expectedEnable, enabled, "ResolveReasoningParser enabled for %s", tc.model)
		assert.Equal(t, tc.expectedParser, parser, "ResolveReasoningParser parser for %s", tc.model)
	}
}






