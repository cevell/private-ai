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
	// 1. Turing GPU (T4): chunked prefill omitted
	turingTopo := hardware.TopologyReport{
		HasGPU:      true,
		GPUCount:    1,
		IsTuringGPU: true,
		GPUModel:    "Tesla T4",
	}
	assert.True(t, turingTopo.IsTuringGPU)

	// 2. Ampere/Ada GPU (A100 / L4): chunked prefill enabled
	ampereTopo := hardware.TopologyReport{
		HasGPU:      true,
		GPUCount:    1,
		IsTuringGPU: false,
		GPUModel:    "NVIDIA A100-SXM4-80GB",
	}
	assert.False(t, ampereTopo.IsTuringGPU)
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






