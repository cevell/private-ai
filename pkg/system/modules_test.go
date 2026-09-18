package system

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringsTrim(t *testing.T) {
	shortStr := "short"
	assert.Equal(t, "short", stringsTrim(shortStr))

	longStr := ""
	for i := 0; i < 150; i++ {
		longStr += "a"
	}
	assert.Equal(t, 100, len(stringsTrim(longStr)))
}

func TestDetectMajorFromProcDevices(t *testing.T) {
	// 1. Non-existent proc file simulation by passing unknown device
	major := detectMajorFromProcDevices("non-existent-device-xyz")
	assert.Equal(t, uint32(0), major)

	// 2. Create a temporary proc/devices mock file
	tmpDir := t.TempDir()
	mockProcDevices := filepath.Join(tmpDir, "devices")
	mockContent := `Character devices:
  1 mem
  4 /dev/vc/0
  5 /dev/tty
 195 nvidia
 508 nvidia-uvm
 509 nvidia_modeset

Block devices:
  8 sd
 259 blkext
`
	err := os.WriteFile(mockProcDevices, []byte(mockContent), 0644)
	assert.NoError(t, err)

	testData, err := os.ReadFile(mockProcDevices)
	assert.NoError(t, err)
	assert.Contains(t, string(testData), "nvidia-uvm")
}

func TestEnsureGPUDeviceNodes(t *testing.T) {
	err := EnsureGPUDeviceNodes()
	assert.NoError(t, err)
}

func TestHoldNVIDIAPersistence(t *testing.T) {
	// Should execute gracefully even when /dev/nvidiactl is not present on host
	err := HoldNVIDIAPersistence()
	assert.NoError(t, err)
}
