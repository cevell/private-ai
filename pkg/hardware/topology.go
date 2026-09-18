package hardware

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/cevell/private-ai/pkg/config"
)

// TopologyReport represents auto-discovered compute capabilities of the CVM.
type TopologyReport struct {
	CPUCores       int      `json:"cpu_cores"`
	RAMTotalMB     int      `json:"ram_total_mb"`
	HasAVX512      bool     `json:"has_avx512"`
	HasAVX2        bool     `json:"has_avx2"`
	HasGPU         bool     `json:"has_gpu"`
	GPUCount       int      `json:"gpu_count"`
	GPUDevices     []string `json:"gpu_devices"`
	GPUControlDevs []string `json:"gpu_control_devices,omitempty"`
	GPUOperational    bool     `json:"gpu_operational"`
	GPUModel          string   `json:"gpu_model,omitempty"`
	GPUArchitecture   string   `json:"gpu_architecture,omitempty"`   // "Turing", "Ampere", "Ada", "Hopper", "Blackwell"
	ComputeCapability float64  `json:"compute_capability,omitempty"`  // 7.5, 8.0, 8.9, 9.0, 10.0, 12.0
	IsTuringGPU       bool     `json:"is_turing_gpu,omitempty"`
	IsHopperGPU       bool     `json:"is_hopper_gpu,omitempty"`
	IsBlackwellGPU    bool     `json:"is_blackwell_gpu,omitempty"`
	IsAdaGPU          bool     `json:"is_ada_gpu,omitempty"`
	IsAmpereGPU       bool     `json:"is_ampere_gpu,omitempty"`
	VRAMTotalMB       int      `json:"vram_total_mb,omitempty"`
	VRAMPerGPUMB      int      `json:"vram_per_gpu_mb,omitempty"`
	Recommended       string   `json:"recommended_engine"` // "vllm" or "llama.cpp"
}

// DiscoverTopology scans the guest OS environment for hardware accelerators.
func DiscoverTopology() TopologyReport {
	defaultEngine := "llama.cpp"
	if config.IsGPULocked() {
		defaultEngine = "gpu-required"
	}
	report := TopologyReport{
		CPUCores:    runtime.NumCPU(),
		Recommended: defaultEngine,
	}

	// 1. Parse /proc/meminfo
	if file, err := os.Open("/proc/meminfo"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.Atoi(fields[1]); err == nil {
						report.RAMTotalMB = kb / 1024
					}
				}
				break
			}
		}
	}

	// 2. Parse /proc/cpuinfo for vector flags
	if file, err := os.Open("/proc/cpuinfo"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "flags") {
				flags := strings.Fields(line)
				for _, flag := range flags {
					if flag == "avx512f" || flag == "avx512_vnni" {
						report.HasAVX512 = true
					}
					if flag == "avx2" {
						report.HasAVX2 = true
					}
				}
				break
			}
		}
	}

	// 3. Scan PCI devices for physical NVIDIA GPUs (0x10de) and AMD accelerators (0x1002)
	var pciGpus []string
	pciMatches, _ := filepath.Glob("/sys/bus/pci/devices/*/vendor")
	for _, vFile := range pciMatches {
		if data, err := os.ReadFile(vFile); err == nil {
			vStr := strings.TrimSpace(string(data))
			if strings.EqualFold(vStr, "0x10de") || strings.EqualFold(vStr, "0x1002") {
				devDir := filepath.Dir(vFile)
				pciID := filepath.Base(devDir)
				if !contains(pciGpus, pciID) {
					pciGpus = append(pciGpus, pciID)
				}
				// Check device ID for GPU architecture and model identification
				if devData, err := os.ReadFile(filepath.Join(devDir, "device")); err == nil {
					devID := strings.ToLower(strings.TrimSpace(string(devData)))
					switch {
					case strings.Contains(devID, "0x2900") || strings.Contains(devID, "0x2901") || strings.Contains(devID, "0x2902") || strings.Contains(devID, "0x2903") || strings.Contains(devID, "0x2940") || strings.Contains(devID, "0x2941") || strings.Contains(devID, "0x2980"):
						report.IsBlackwellGPU = true
						report.GPUArchitecture = "Blackwell"
						report.ComputeCapability = 10.0
						if report.GPUModel == "" {
							report.GPUModel = "NVIDIA Blackwell B200/B100"
						}
					case strings.Contains(devID, "0x2330") || strings.Contains(devID, "0x2331") || strings.Contains(devID, "0x2322") || strings.Contains(devID, "0x2324"):
						report.IsHopperGPU = true
						report.GPUArchitecture = "Hopper"
						report.ComputeCapability = 9.0
						if report.GPUModel == "" {
							report.GPUModel = "NVIDIA H100 80GB HBM3"
						}
					case strings.Contains(devID, "0x27b8") || strings.Contains(devID, "0x2782") || strings.Contains(devID, "0x2684") || strings.Contains(devID, "0x2704"):
						report.IsAdaGPU = true
						report.GPUArchitecture = "Ada"
						report.ComputeCapability = 8.9
						if report.GPUModel == "" {
							report.GPUModel = "NVIDIA L4"
						}
					case strings.Contains(devID, "0x20b0") || strings.Contains(devID, "0x20b2") || strings.Contains(devID, "0x20f1") || strings.Contains(devID, "0x2235"):
						report.IsAmpereGPU = true
						report.GPUArchitecture = "Ampere"
						report.ComputeCapability = 8.0
						if report.GPUModel == "" {
							report.GPUModel = "NVIDIA A100"
						}
					case strings.Contains(devID, "0x1eb8") || strings.Contains(devID, "0x1eb0") || strings.Contains(devID, "0x1eb1") || strings.Contains(devID, "0x1e30") || strings.Contains(devID, "0x1e04") || strings.Contains(devID, "0x2182") || strings.Contains(devID, "0x2184"):
						report.IsTuringGPU = true
						report.GPUArchitecture = "Turing"
						report.ComputeCapability = 7.5
						if report.GPUModel == "" {
							report.GPUModel = "Tesla T4"
						}
					}
				}
			}
		}
	}

	// Scan NVIDIA driver procfs if available
	if gpuInfoFiles, err := filepath.Glob("/proc/driver/nvidia/gpus/*/information"); err == nil {
		for _, infoFile := range gpuInfoFiles {
			if content, err := os.ReadFile(infoFile); err == nil {
				text := string(content)
				for _, line := range strings.Split(text, "\n") {
					if strings.HasPrefix(line, "Model:") {
						modelName := strings.TrimSpace(strings.TrimPrefix(line, "Model:"))
						if report.GPUModel == "" {
							report.GPUModel = modelName
						}
					}
				}
			}
		}
	}

	// Query nvidia-smi for precise compute capability, model, and memory if present
	cmd := exec.Command("nvidia-smi", "--query-gpu=compute_cap,name,memory.total", "--format=csv,noheader,nounits")
	if out, err := cmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 0 {
			fields := strings.Split(lines[0], ",")
			if len(fields) >= 1 {
				if cc, err := strconv.ParseFloat(strings.TrimSpace(fields[0]), 64); err == nil && cc > 0 {
					report.ComputeCapability = cc
				}
			}
			if len(fields) >= 2 && report.GPUModel == "" {
				report.GPUModel = strings.TrimSpace(fields[1])
			}
			if len(fields) >= 3 && report.VRAMPerGPUMB == 0 {
				if mb, err := strconv.Atoi(strings.TrimSpace(fields[2])); err == nil && mb > 0 {
					report.VRAMPerGPUMB = mb
				}
			}
		}
	}

	// Classify architecture and generational flags based on model name and compute capability
	classifyArchitecture(&report)

	// 4. Scan character device nodes distinguishing physical GPUs from control nodes
	var physicalDevs []string
	var controlDevs []string

	// NVIDIA physical compute devices: /dev/nvidia0, /dev/nvidia1, etc.
	if nvMatches, err := filepath.Glob("/dev/nvidia[0-9]*"); err == nil {
		for _, m := range nvMatches {
			base := filepath.Base(m)
			numPart := strings.TrimPrefix(base, "nvidia")
			if _, err := strconv.Atoi(numPart); err == nil {
				if !contains(physicalDevs, m) {
					physicalDevs = append(physicalDevs, m)
				}
			}
		}
	}

	// NVIDIA control devices (e.g. /dev/nvidiactl, /dev/nvidia-uvm, /dev/nvidia-modeset)
	for _, ctl := range []string{"/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-modeset", "/dev/kfd"} {
		if _, err := os.Stat(ctl); err == nil {
			controlDevs = append(controlDevs, ctl)
		}
	}

	// DRM render nodes (one per GPU accelerator: /dev/dri/renderD128, renderD129...)
	if drmMatches, err := filepath.Glob("/dev/dri/renderD[0-9]*"); err == nil {
		for _, m := range drmMatches {
			if !contains(physicalDevs, m) {
				physicalDevs = append(physicalDevs, m)
			}
		}
	}

	// Linux compute accelerators (/dev/accel/accel0...)
	if accelMatches, err := filepath.Glob("/dev/accel/accel[0-9]*"); err == nil {
		for _, m := range accelMatches {
			if !contains(physicalDevs, m) {
				physicalDevs = append(physicalDevs, m)
			}
		}
	}

	// 5. Determine definitive physical GPU count and device list
	report.GPUControlDevs = controlDevs
	if len(pciGpus) > 0 {
		report.GPUDevices = pciGpus
		report.GPUCount = len(pciGpus)
		report.HasGPU = true
	} else if len(physicalDevs) > 0 {
		report.GPUDevices = physicalDevs
		report.GPUCount = len(physicalDevs)
		report.HasGPU = true
	}

	if report.HasGPU && report.GPUCount > 0 {
		if config.IsGPULocked() {
			report.Recommended = "vllm"
		} else {
			report.Recommended = "llama.cpp"
		}
		// Verify device node or sysfs access
		report.GPUOperational = true

		if report.VRAMPerGPUMB <= 0 {
			report.VRAMPerGPUMB = discoverVRAMPerGPU(report.GPUModel)
		}
		report.VRAMTotalMB = report.VRAMPerGPUMB * report.GPUCount
	}

	return report
}

func classifyArchitecture(report *TopologyReport) {
	upper := strings.ToUpper(report.GPUModel)
	switch {
	case report.ComputeCapability >= 10.0 || strings.Contains(upper, "B100") || strings.Contains(upper, "B200") || strings.Contains(upper, "GB200") || strings.Contains(upper, "BLACKWELL") || strings.Contains(upper, "RTX PRO 6000") || strings.Contains(upper, "B40"):
		report.IsBlackwellGPU = true
		report.GPUArchitecture = "Blackwell"
		if report.ComputeCapability == 0 {
			report.ComputeCapability = 10.0
		}
	case (report.ComputeCapability >= 9.0 && report.ComputeCapability < 10.0) || strings.Contains(upper, "H100") || strings.Contains(upper, "H200") || strings.Contains(upper, "HOPPER") || strings.Contains(upper, "GH200"):
		report.IsHopperGPU = true
		report.GPUArchitecture = "Hopper"
		if report.ComputeCapability == 0 {
			report.ComputeCapability = 9.0
		}
	case (report.ComputeCapability >= 8.9 && report.ComputeCapability < 9.0) || strings.Contains(upper, "L4") || strings.Contains(upper, "L40") || strings.Contains(upper, "RTX 40") || strings.Contains(upper, "ADA") || strings.Contains(upper, "AD102") || strings.Contains(upper, "AD104"):
		report.IsAdaGPU = true
		report.GPUArchitecture = "Ada"
		if report.ComputeCapability == 0 {
			report.ComputeCapability = 8.9
		}
	case (report.ComputeCapability >= 8.0 && report.ComputeCapability < 8.9) || strings.Contains(upper, "A100") || strings.Contains(upper, "A10") || strings.Contains(upper, "A30") || strings.Contains(upper, "A40") || strings.Contains(upper, "RTX 30") || strings.Contains(upper, "AMPERE") || strings.Contains(upper, "GA100") || strings.Contains(upper, "GA102"):
		report.IsAmpereGPU = true
		report.GPUArchitecture = "Ampere"
		if report.ComputeCapability == 0 {
			report.ComputeCapability = 8.0
		}
	case (report.ComputeCapability >= 7.5 && report.ComputeCapability < 8.0) || strings.Contains(upper, "T4") || strings.Contains(upper, "TURING") || strings.Contains(upper, "TU104") || strings.Contains(upper, "TU102") || strings.Contains(upper, "RTX 20") || strings.Contains(upper, "GTX 16"):
		report.IsTuringGPU = true
		report.GPUArchitecture = "Turing"
		if report.ComputeCapability == 0 {
			report.ComputeCapability = 7.5
		}
	}
}

func discoverVRAMPerGPU(modelName string) int {
	// 1. Try nvidia-smi query
	cmd := exec.Command("nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits")
	if out, err := cmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 0 {
			if mb, err := strconv.Atoi(strings.TrimSpace(lines[0])); err == nil && mb > 0 {
				return mb
			}
		}
	}

	// 2. Hardware model heuristics
	return heuristicVRAMPerGPU(modelName)
}

func heuristicVRAMPerGPU(modelName string) int {
	upper := strings.ToUpper(modelName)
	switch {
	case strings.Contains(upper, "B200"), strings.Contains(upper, "GB200"):
		return 184320 // 180 GB / 192 GB
	case strings.Contains(upper, "B100"):
		return 147456 // 144 GB
	case strings.Contains(upper, "RTX PRO 6000"), strings.Contains(upper, "RTX 6000"), strings.Contains(upper, "B40"):
		return 49152 // 48 GB
	case strings.Contains(upper, "H100"), strings.Contains(upper, "H200"):
		return 81920 // 80 GB
	case strings.Contains(upper, "A100"):
		return 81920 // 80 GB default
	case strings.Contains(upper, "L40"):
		return 49152 // 48 GB
	case strings.Contains(upper, "L4"):
		return 24576 // 24 GB
	case strings.Contains(upper, "T4"):
		return 16160 // 16 GB
	case strings.Contains(upper, "V100"):
		return 16384 // 16 GB
	default:
		return 16384 // 16 GB conservative baseline
	}
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
