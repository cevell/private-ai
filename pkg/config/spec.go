package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Target constants for build-time and runtime target selection.
const (
	TargetCPU = "cpu"
	TargetGPU = "gpu"
)

// BuildTarget is injected at compile time via:
// -ldflags "-X github.com/cevell/private-ai/pkg/config.BuildTarget=cpu" (or "gpu")
// Defaults to "gpu".
var BuildTarget = TargetGPU

// BuildDebug is injected at compile time via:
// -ldflags "-X github.com/cevell/private-ai/pkg/config.BuildDebug=on" (or "off")
var BuildDebug = ""

// ActiveTarget allows runtime override if needed (e.g. from config spec).
var activeTarget string

var (
	debugMode   *bool
	debugModeMu sync.RWMutex
)

// SetDebugMode explicitly enables or disables debug mode at runtime.
func SetDebugMode(enabled bool) {
	debugModeMu.Lock()
	defer debugModeMu.Unlock()
	b := enabled
	debugMode = &b
}

// IsDebugMode resolves whether debug mode is enabled.
// Returns an error if the mandatory debug flag was never specified anywhere.
func IsDebugMode() (bool, error) {
	debugModeMu.RLock()
	if debugMode != nil {
		defer debugModeMu.RUnlock()
		return *debugMode, nil
	}
	debugModeMu.RUnlock()

	debugModeMu.Lock()
	defer debugModeMu.Unlock()
	if debugMode != nil {
		return *debugMode, nil
	}

	// 1. Check compile-time injection
	if BuildDebug != "" {
		val := strings.ToLower(strings.TrimSpace(BuildDebug))
		if val == "on" || val == "1" || val == "true" {
			b := true
			debugMode = &b
			return true, nil
		}
		if val == "off" || val == "0" || val == "false" {
			b := false
			debugMode = &b
			return false, nil
		}
	}

	// 2. Check environment variable DEBUG
	if val := strings.ToLower(strings.TrimSpace(os.Getenv("DEBUG"))); val != "" {
		if val == "on" || val == "1" || val == "true" {
			b := true
			debugMode = &b
			return true, nil
		}
		if val == "off" || val == "0" || val == "false" {
			b := false
			debugMode = &b
			return false, nil
		}
	}

	// 3. Check kernel command line (/proc/cmdline)
	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmdline := string(data)
		for _, token := range strings.Fields(cmdline) {
			token = strings.ToLower(token)
			if token == "debug=on" || token == "debug=1" {
				b := true
				debugMode = &b
				return true, nil
			}
			if token == "debug=off" || token == "debug=0" {
				b := false
				debugMode = &b
				return false, nil
			}
		}
	}

	return false, errors.New("mandatory debug flag is not present: must explicitly set DEBUG=on or DEBUG=off in environment, build flags, or kernel cmdline")
}

// MustIsDebugMode returns true if debug is on, false if off, panics if unspecified.
func MustIsDebugMode() bool {
	on, err := IsDebugMode()
	if err != nil {
		panic(err)
	}
	return on
}

// SetTarget sets the active target at runtime.
func SetTarget(target string) {
	if strings.EqualFold(target, TargetCPU) {
		activeTarget = TargetCPU
	} else {
		activeTarget = TargetGPU
	}
}

// GetTarget returns the effective target ("cpu" or "gpu").
func GetTarget() string {
	if activeTarget != "" {
		return activeTarget
	}
	if strings.EqualFold(BuildTarget, TargetCPU) {
		return TargetCPU
	}
	return TargetGPU
}

// IsGPULocked returns true if the node is operating in strict GPU-locked mode.
func IsGPULocked() bool {
	return GetTarget() == TargetGPU
}

// NodeSpec defines the top-level configuration for an Cevell CVM deployment.
type NodeSpec struct {
	Version      string           `yaml:"version"`
	Domain       string           `yaml:"domain,omitempty"`
	Debug        *bool            `yaml:"debug,omitempty"`
	Confidential ConfidentialSpec `yaml:"confidential"`
	Workload     WorkloadSpec     `yaml:"workload"`
	Hardware     HardwareSpec     `yaml:"hardware,omitempty"`
	Telemetry    TelemetrySpec    `yaml:"telemetry,omitempty"`
}

type ConfidentialSpec struct {
	Platform         string `yaml:"platform"`          // "amd-sev-snp", "intel-tdx", "auto"
	RequireVLEK      bool   `yaml:"require_vlek"`
	DummyAttestation bool   `yaml:"dummy_attestation"`
}

type WorkloadSpec struct {
	Containers []ContainerSpec `yaml:"containers"`
	Port       int             `yaml:"port"`
}

type ContainerSpec struct {
	Name        string            `yaml:"name"`
	Image       string            `yaml:"image"`
	Digest      string            `yaml:"digest,omitempty"`
	Entrypoint  []string          `yaml:"entrypoint,omitempty"`
	Command     []string          `yaml:"command,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
	PortMap     map[int]int       `yaml:"ports,omitempty"`
	RequiresGPU bool              `yaml:"gpu,omitempty"`
}

type HardwareSpec struct {
	Target       string  `yaml:"target,omitempty"`        // "cpu" or "gpu"
	GPUOnly      bool    `yaml:"gpu_only,omitempty"`      // true for strict GPU lockdown
	VRAMFraction float64 `yaml:"vram_fraction,omitempty"` // Default: 0.90 / 0.95
	AutoTune     bool    `yaml:"auto_tune,omitempty"`
}

type TelemetrySpec struct {
	Enabled       bool   `yaml:"enabled"`
	MetricsAPIKey string `yaml:"metrics_api_key,omitempty"`
}

// LoadNodeSpec loads and parses a YAML configuration file from disk.
func LoadNodeSpec(path string) (*NodeSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var spec NodeSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing YAML spec: %w", err)
	}

	if spec.Version == "" {
		spec.Version = "v1"
	}
	if spec.Workload.Port == 0 {
		spec.Workload.Port = 8000
	}
	if spec.Debug != nil {
		SetDebugMode(*spec.Debug)
	}

	return &spec, nil
}
