package system

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureConsoleLockdown(t *testing.T) {
	// 1. Enable debug
	err := ConfigureConsoleLockdown(true)
	require.NoError(t, err)
	assert.True(t, IsConsoleDebugActive())

	Log("test log debug on")
	logs := GetRecentSystemLogs()
	assert.NotEmpty(t, logs)
	assert.Contains(t, logs[len(logs)-1], "test log debug on")

	// 2. Disable debug (strict lockdown)
	err = ConfigureConsoleLockdown(false)
	require.NoError(t, err)
	assert.False(t, IsConsoleDebugActive())

	Log("test log debug off")
	logsAfter := GetRecentSystemLogs()
	assert.Contains(t, logsAfter[len(logsAfter)-1], "test log debug off")

	// 3. Re-enable debug
	err = ConfigureConsoleLockdown(true)
	require.NoError(t, err)
	assert.True(t, IsConsoleDebugActive())
}
