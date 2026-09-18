package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadNodeSpec(t *testing.T) {
	yamlContent := `version: "v1"
domain: "test.cevell.com"
confidential:
  platform: "amd-sev-snp"
workload:
  port: 8080
  containers:
    - name: "vllm-gpu-inference"
      image: "vllm/vllm-openai:latest"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "cvm-spec.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yamlContent), 0644))

	spec, err := LoadNodeSpec(configPath)
	require.NoError(t, err)
	require.NotNil(t, spec)

	assert.Equal(t, "v1", spec.Version)
	assert.Equal(t, "test.cevell.com", spec.Domain)
	assert.Equal(t, 8080, spec.Workload.Port)
	assert.Equal(t, 1, len(spec.Workload.Containers))
	assert.Equal(t, "vllm-gpu-inference", spec.Workload.Containers[0].Name)

	assert.NoError(t, spec.Validate())
}

func TestTargetResolution(t *testing.T) {
	// Test Default (GPU)
	SetTarget("")
	assert.Equal(t, TargetGPU, GetTarget())
	assert.True(t, IsGPULocked())

	// Test Setting CPU
	SetTarget("cpu")
	assert.Equal(t, TargetCPU, GetTarget())
	assert.False(t, IsGPULocked())

	// Test Setting GPU
	SetTarget("gpu")
	assert.Equal(t, TargetGPU, GetTarget())
	assert.True(t, IsGPULocked())

	// Reset to default
	SetTarget("")
}

func TestDebugResolution(t *testing.T) {
	// 1. Explicitly Set Debug True
	SetDebugMode(true)
	val, err := IsDebugMode()
	require.NoError(t, err)
	assert.True(t, val)

	// 2. Explicitly Set Debug False
	SetDebugMode(false)
	val, err = IsDebugMode()
	require.NoError(t, err)
	assert.False(t, val)
}
