package system

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStartZombieReaperNonPID1(t *testing.T) {
	// In test environment, process is not PID 1.
	// Calling StartZombieReaper should safely return without error.
	assert.NotPanics(t, func() {
		StartZombieReaper()
	})
}

func TestSpawnZombieReaper(t *testing.T) {
	// SpawnZombieReaper should initialize cleanly and listen in background.
	assert.NotPanics(t, func() {
		SpawnZombieReaper()
	})
}
