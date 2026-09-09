package inference

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cevell/private-ai/pkg/config"
	"github.com/cevell/private-ai/pkg/hardware"
	"github.com/cevell/private-ai/pkg/system"
)

// ModelSpec defines the parameters for dynamic model loading.
type ModelSpec struct {
	Model       string  `json:"model"`                  // HuggingFace ID, GGUF URL, or local path
	HFFile      string  `json:"hf_file,omitempty"`      // Specific GGUF file in Hugging Face repo
	HFToken     string  `json:"hf_token,omitempty"`     // Hugging Face token for gated models
	ContextSize    int     `json:"context_size,omitempty"` // Context window (tokens)
	Temperature    float64 `json:"temperature,omitempty"`  // Sampling temperature
	GPULayers      int     `json:"gpu_layers,omitempty"`   // Number of layers to offload to GPU (CPU mode)
	Threads        int     `json:"threads,omitempty"`      // CPU threads
	ExposeInHealth *bool   `json:"expose_in_health"`       // Mandatory: true (public on /v1/health) or false (confidential)
}

// Supervisor manages the lifecycle of the active inference engine.
type Supervisor struct {
	mu             sync.RWMutex
	loadMu         sync.Mutex
	currentCmd     *exec.Cmd
	currentModel   string
	backendType    string
	engineReady    bool
	port           int
	topo           hardware.TopologyReport
	fatalError     error
	livenessCancel context.CancelFunc
	maxContext     int
	activeContext  int
	exposeInHealth bool

	activityMu   sync.RWMutex
	lastActivity time.Time
}

// killProcessGroup sends SIGTERM to the process group, waits up to 2 seconds, and escalates to SIGKILL.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 1 {
		return nil
	}
	pgid := cmd.Process.Pid
	system.Log("Terminating inference process group (PGID: %d)...", pgid)

	// 1. Send SIGTERM to process group
	_ = syscall.Kill(-pgid, syscall.SIGTERM)

	// 2. Wait up to 2 seconds for clean exit
	done := make(chan struct{})
	go func() {
		if cmd.Process != nil {
			_, _ = cmd.Process.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
		// Ensure no detached/hung tensor parallel workers remain in the process group
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return nil
	case <-time.After(2 * time.Second):
		// 3. Force kill entire process group
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			system.LogError("[supervisor] Process group %d did not terminate after SIGKILL within 3s", pgid)
		}
		return nil
	}
}

// cleanupStaleCacheArtifacts purges dangling lock files and incomplete downloads from cache,
// and ensures temporary JIT directories exist with correct permissions.
func cleanupStaleCacheArtifacts() {
	cacheDir := "/mnt/ramdisk/cache"
	if _, err := os.Stat(cacheDir); err == nil {
		_ = filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && (strings.HasSuffix(path, ".lock") || strings.HasSuffix(path, ".incomplete")) {
				_ = os.Remove(path)
			}
			return nil
		})
	}
	for _, sub := range []string{
		"/mnt/ramdisk/tmp/triton",
		"/mnt/ramdisk/tmp/cuda_cache",
		"/mnt/ramdisk/tmp/torch_ext",
	} {
		_ = os.RemoveAll(sub)
	}
	_ = os.MkdirAll("/mnt/ramdisk/tmp/triton", 0777)
	_ = os.MkdirAll("/mnt/ramdisk/tmp/cuda_cache", 0777)
	_ = os.MkdirAll("/mnt/ramdisk/tmp/torch_ext", 0777)
	_ = os.Chmod("/mnt/ramdisk/tmp", 01777)
	if os.Getuid() == 0 {
		_ = os.Chown("/mnt/ramdisk/tmp", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/tmp/triton", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/tmp/cuda_cache", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/tmp/torch_ext", 1000, 1000)
	}
}

// startLivenessProber continuously verifies that the active inference engine remains healthy.
func (s *Supervisor) startLivenessProber(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0
	client := &http.Client{Timeout: 3 * time.Second}
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/health", s.port)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			ready := s.engineReady
			s.mu.RUnlock()

			if !ready {
				return
			}

			// Decouple probing from active inference:
			// If the engine has produced tokens or completed requests recently (within 30s),
			// it is demonstrably alive and actively computing. Probing its single-threaded HTTP
			// event loop during heavy GPU prefill or generation causes spurious probe timeouts
			// that falsely kill healthy engines.
			s.activityMu.RLock()
			recentActivity := time.Since(s.lastActivity) < 30*time.Second
			s.activityMu.RUnlock()

			if recentActivity {
				consecutiveFailures = 0
				continue
			}

			resp, err := client.Get(healthURL)
			if err != nil || resp.StatusCode != http.StatusOK {
				consecutiveFailures++
				if resp != nil {
					_ = resp.Body.Close()
				}
				if consecutiveFailures >= 3 {
					s.mu.Lock()
					s.engineReady = false
					s.fatalError = fmt.Errorf("vLLM engine health probe failed (unresponsive)")
					cmdToKill := s.currentCmd
					s.currentCmd = nil
					s.mu.Unlock()
					system.LogError("vLLM engine health probe failed 3 consecutive times: %v. Terminating unresponsive engine process group...", err)
					if cmdToKill != nil {
						_ = killProcessGroup(cmdToKill)
					}
					return
				}
			} else {
				consecutiveFailures = 0
				_ = resp.Body.Close()
				s.RecordActivity()
			}
		}
	}
}

// NewSupervisor initializes an inference workload supervisor.
func NewSupervisor(port int) *Supervisor {
	if port <= 0 {
		port = 8000
	}
	topo := hardware.DiscoverTopology()
	var fatalErr error
	backend := "llama.cpp"

	if config.IsGPULocked() {
		backend = "vllm"
		if !topo.HasGPU || topo.GPUCount <= 0 {
			fatalErr = fmt.Errorf("fatal: GPU-locked CVM initialized without physical GPU hardware (GPUCount=%d)", topo.GPUCount)
		}
	}

	return &Supervisor{
		port:         port,
		backendType:  backend,
		topo:         topo,
		fatalError:   fatalErr,
		lastActivity: time.Now(),
	}
}

// RecordActivity updates the timestamp of the last known engine activity (e.g. token streamed, request completed).
func (s *Supervisor) RecordActivity() {
	if s == nil {
		return
	}
	s.activityMu.Lock()
	s.lastActivity = time.Now()
	s.activityMu.Unlock()
}

// LastActivity returns the timestamp of the most recent engine activity.
func (s *Supervisor) LastActivity() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.activityMu.RLock()
	defer s.activityMu.RUnlock()
	return s.lastActivity
}

// SetFatalError sets an unrecoverable system/hardware error on the supervisor.
func (s *Supervisor) SetFatalError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fatalError = err
}

// FatalError returns the current fatal hardware/system error, if any.
func (s *Supervisor) FatalError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fatalError
}

// IsReady reports whether the inference engine is online and accepting requests.
func (s *Supervisor) IsReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.engineReady
}

// SetReadyForTest sets the engine ready state for unit and integration testing.
func (s *Supervisor) SetReadyForTest(ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engineReady = ready
}

// CurrentModel returns the currently loaded model name.
func (s *Supervisor) CurrentModel() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentModel
}

// BackendType returns the active engine type ("vllm" or "llama.cpp").
func (s *Supervisor) BackendType() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backendType
}

// MaxContext returns the maximum viable context window supported by the active model and hardware.
func (s *Supervisor) MaxContext() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxContext
}

// ActiveContext returns the currently active allocated context window size.
func (s *Supervisor) ActiveContext() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeContext
}

// ExposeInHealth reports whether the current model identifier may be published on unauthenticated /v1/health.
func (s *Supervisor) ExposeInHealth() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exposeInHealth
}

// Port returns the local loopback port of the backend inference engine.
func (s *Supervisor) Port() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.port
}

// SynchronizeDriverVRAMClearance waits for the NVIDIA kernel driver to finish asynchronous memory reclamation
// following process group termination before launching a new model process.
func (s *Supervisor) SynchronizeDriverVRAMClearance(timeout time.Duration) {
	s.mu.RLock()
	topo := s.topo
	s.mu.RUnlock()

	if !topo.HasGPU || topo.GPUCount <= 0 {
		return
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.Command("nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits")
		out, err := cmd.Output()
		if err != nil {
			// nvidia-smi not available in environment or error; fall back to brief sleep
			time.Sleep(200 * time.Millisecond)
			return
		}

		allClear := true
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			usedMB, err := strconv.Atoi(line)
			if err == nil {
				// Idle GPU baseline driver memory is typically < 250 MB
				if usedMB > 500 {
					allClear = false
					break
				}
			}
		}

		if allClear {
			system.Log("[supervisor] NVIDIA driver VRAM reclamation verified: GPU memory cleared")
			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	system.Log("WARNING: [supervisor] Timeout waiting for NVIDIA driver VRAM clearance; proceeding with model initialization")
}

// LoadModel dynamically terminates any running engine and starts the requested model.
func (s *Supervisor) LoadModel(ctx context.Context, spec ModelSpec) error {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()

	// 1. Terminate existing engine process and liveness prober safely
	s.mu.Lock()
	if s.livenessCancel != nil {
		s.livenessCancel()
		s.livenessCancel = nil
	}
	oldCmd := s.currentCmd
	s.currentCmd = nil
	s.engineReady = false
	s.fatalError = nil
	s.mu.Unlock()

	if oldCmd != nil && oldCmd.Process != nil {
		system.Log("Terminating active inference engine (%s)...", s.CurrentModel())
		_ = killProcessGroup(oldCmd)
		// Synchronize with NVIDIA driver to allow asynchronous VRAM reclamation before launching new model
		s.SynchronizeDriverVRAMClearance(5 * time.Second)
	}

	if strings.TrimSpace(spec.Model) == "" {
		return fmt.Errorf("model identifier is required (e.g. 'Qwen/Qwen2.5-0.5B-Instruct' or 'model.gguf')")
	}
	// Sanitize and validate model specification against argument/command injection
	if strings.HasPrefix(spec.Model, "-") || strings.ContainsAny(spec.Model, "\x00\r\n\t;`$|&><") {
		return fmt.Errorf("invalid model identifier: contains forbidden characters or flag prefix")
	}
	if spec.HFFile != "" && (strings.HasPrefix(spec.HFFile, "-") || strings.ContainsAny(spec.HFFile, "\x00\r\n\t;`$|&><")) {
		return fmt.Errorf("invalid hf_file parameter: contains forbidden characters or flag prefix")
	}
	if spec.HFToken != "" && strings.ContainsAny(spec.HFToken, "\x00\r\n") {
		return fmt.Errorf("invalid hf_token parameter: contains forbidden newline or null characters")
	}
	if spec.ExposeInHealth == nil {
		return fmt.Errorf("missing required parameter 'expose_in_health': must be explicitly set to true (publicly visible on unauthenticated /v1/health) or false (confidential)")
	}
	topo := hardware.DiscoverTopology()

	// Pre-flight assessment of model architecture and VRAM capacity
	meta := InspectModelMetadata(spec.Model, spec.HFToken)
	shouldClamp, safeContext := EvaluateVRAMContextBudget(meta, topo, spec.ContextSize)

	if shouldClamp && safeContext > 0 {
		if spec.ContextSize > 0 {
			system.Log("Applying user-specified context length: %d tokens for %s", safeContext, spec.Model)
		} else {
			system.Log("[VRAM Protection] Constrained VRAM detected. Clamping context length to safe ceiling: %d tokens (%s) for %s",
				safeContext, FormatContextSize(safeContext), spec.Model)
		}
		spec.ContextSize = safeContext
	} else {
		// VRAM is plenty or unknown: resolve to requested context or model native max (fallback 4096)
		resolvedContext := spec.ContextSize
		if resolvedContext <= 0 {
			if meta.ModelNativeMax > 0 {
				resolvedContext = meta.ModelNativeMax
			} else {
				resolvedContext = 4096
			}
		}
		spec.ContextSize = resolvedContext
		system.Log("VRAM headroom verified: configured context length to %d tokens (%s) for %s",
			spec.ContextSize, FormatContextSize(spec.ContextSize), spec.Model)
	}

	s.mu.Lock()
	s.topo = topo
	s.currentModel = spec.Model
	s.maxContext = meta.ModelNativeMax
	s.activeContext = spec.ContextSize
	s.exposeInHealth = *spec.ExposeInHealth
	s.mu.Unlock()

	// Ensure writable ramdisk directories and purge stale artifacts
	cleanupStaleCacheArtifacts()
	_ = os.MkdirAll("/mnt/ramdisk/models", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/cache", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/home", 0755)
	_ = os.MkdirAll("/tmp", 0777)
	_ = os.MkdirAll("/var/tmp", 0777)

	if config.IsGPULocked() {
		if !topo.HasGPU || topo.GPUCount <= 0 {
			err := fmt.Errorf("vLLM GPU Lock Enforcement: no physical GPU hardware detected (GPUCount=%d). CPU execution is strictly disabled", topo.GPUCount)
			s.SetFatalError(err)
			return err
		}
		return s.loadGPUModel(ctx, spec, meta)
	}
	return s.loadCPUModel(ctx, spec)
}

// AlignTensorParallelToKVHeads calculates the optimal tensor parallel size such that
// it does not exceed the available GPU count and evenly divides the model's KV attention heads (INF-03).
func AlignTensorParallelToKVHeads(gpuCount, numKVHeads int) int {
	if gpuCount <= 1 {
		return 1
	}
	if numKVHeads <= 0 {
		return gpuCount
	}
	for tp := gpuCount; tp >= 1; tp-- {
		if numKVHeads%tp == 0 {
			return tp
		}
	}
	return 1
}

// loadGPUModel launches vLLM with strict GPU lockdown (CPU fallback is strictly prohibited).
func (s *Supervisor) loadGPUModel(ctx context.Context, spec ModelSpec, meta ModelArchitectureMeta) error {
	s.mu.RLock()
	topo := s.topo
	s.mu.RUnlock()

	if !topo.HasGPU || topo.GPUCount <= 0 {
		err := fmt.Errorf("vLLM GPU Lock Enforcement: no physical GPU hardware detected (GPUCount=%d). CPU execution is strictly disabled", topo.GPUCount)
		s.SetFatalError(err)
		return err
	}

	s.mu.Lock()
	s.backendType = "vllm"
	s.mu.Unlock()

	system.Log("Provisioning model %s on vLLM GPU engine (GPU count: %d, devices: %v, CPUs: %d)...",
		spec.Model, topo.GPUCount, topo.GPUDevices, topo.CPUCores)

	// Clean stale cache artifacts before provisioning runtime or launching engine
	cleanupStaleCacheArtifacts()

	// Dynamically provision vLLM runtime in encrypted RAM if not already present
	if err := ensureVLLMEnvironment(); err != nil {
		system.LogError("vLLM runtime environment setup error: %v", err)
		return err
	}

	binPath, prefixArgs, engineName := findGPUInferenceBinary()
	if binPath == "" {
		return fmt.Errorf("vLLM inference binary not found in system or /mnt/ramdisk/vllm")
	}

	tensorParallel := AlignTensorParallelToKVHeads(topo.GPUCount, meta.NumKVHeads)
	if tensorParallel < topo.GPUCount {
		system.Log("[KV-Head Alignment] Clamping tensor-parallel-size from %d to %d (NumKVHeads=%d)",
			topo.GPUCount, tensorParallel, meta.NumKVHeads)
	}

	var args []string
	args = append(args, prefixArgs...)
	args = append(args,
		spec.Model,
		"--host", "127.0.0.1",
		"--port", fmt.Sprintf("%d", s.port),
		"--device", "cuda", // STRICT GPU LOCK: enforce CUDA hardware execution only
		"--gpu-memory-utilization", "0.90",
		"--swap-space", "0", // Zero CPU swap space for KV cache
		"--cpu-offload-gb", "0", // Strictly disable CPU RAM offloading
		"--tensor-parallel-size", fmt.Sprintf("%d", tensorParallel),
		"--block-size", "16", // Standard PagedAttention block size for GPU VRAM allocation
		"--disable-async-output-proc",
		"--enforce-eager",
	)
	if spec.ContextSize > 0 {
		args = append(args, "--max-model-len", fmt.Sprintf("%d", spec.ContextSize))
	} else {
		args = append(args, "--max-model-len", "4096")
	}

	// Explicit worker class prevents vLLM UnspecifiedPlatform fallback crash
	// where worker_cls="auto" causes ValueError in resolve_obj_by_qualname
	args = append(args, "--worker-cls", "vllm.worker.worker.Worker")

	// Architecture-aware tuning:
	// On Turing (Tesla T4, CC 7.5): omit chunked-prefill and prefix-caching to prevent eager XFormers attention exceptions,
	// and set dtype to half (float16) because Turing does not support native bfloat16.
	// On Ampere/Ada/Hopper (CC 8.0+): enable chunked-prefill, prefix-caching, and auto dtype.
	if !topo.IsTuringGPU {
		args = append(args, "--enable-chunked-prefill", "--enable-prefix-caching", "--dtype", "auto")
	} else {
		args = append(args, "--dtype", "half")
	}

	system.Log("Launching GPU-locked inference engine [%s]: %s %s", engineName, binPath, strings.Join(args, " "))

	cudaDevices := "0"
	if tensorParallel > 1 {
		var devIndices []string
		for i := 0; i < tensorParallel; i++ {
			devIndices = append(devIndices, fmt.Sprintf("%d", i))
		}
		cudaDevices = strings.Join(devIndices, ",")
	}

	cmd := exec.Command(binPath, args...)
	configureSandboxProcAttr(cmd)
	cmd.Env = []string{
		"PATH=/mnt/ramdisk/vllm/bin:/usr/local/cuda/bin:/usr/bin:/usr/sbin:/bin:/sbin",
		"HOME=/mnt/ramdisk/home",
		"HF_HOME=/mnt/ramdisk/cache",
		"HF_HUB_ENABLE_HF_TRANSFER=1",
		"TMPDIR=/mnt/ramdisk/tmp",
		"TRITON_CACHE_DIR=/mnt/ramdisk/tmp/triton",
		"CUDA_CACHE_PATH=/mnt/ramdisk/tmp/cuda_cache",
		"TORCH_EXTENSIONS_DIR=/mnt/ramdisk/tmp/torch_ext",
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"VLLM_TARGET_DEVICE=cuda", // STRICT GPU LOCK: enforce CUDA backend inside vLLM
		"VLLM_ALLOW_LONG_MAX_MODEL_LEN=1",
		"CUDA_VISIBLE_DEVICES=" + cudaDevices,
		"CUDA_DEVICE_ORDER=PCI_BUS_ID",
		"NVIDIA_VISIBLE_DEVICES=all",
		"NVIDIA_DRIVER_CAPABILITIES=compute,utility",
		"LD_LIBRARY_PATH=/mnt/ramdisk/vllm/lib:/mnt/ramdisk/vllm/lib64:/usr/lib/x86_64-linux-gnu:/usr/lib64:/lib64:/lib:/usr/local/cuda/lib64:/usr/local/cuda/lib",
	}
	if topo.GPUCount > 1 {
		cmd.Env = append(cmd.Env,
			"NCCL_P2P_DISABLE=1",
			"NCCL_IB_DISABLE=1",
			"NCCL_DEBUG=INFO",
			"NCCL_BUFFSIZE=2097152",
		)
	}
	if spec.HFToken != "" {
		cmd.Env = append(cmd.Env,
			"HF_TOKEN="+spec.HFToken,
			"HUGGING_FACE_HUB_TOKEN="+spec.HFToken,
		)
	}

	return s.runEngineProcess(ctx, cmd, "[vllm]")
}

func ensureVLLMEnvironment() error {
	_ = system.EnsureGPUDeviceNodes()
	cleanupStaleCacheArtifacts()

	sentinelPath := "/mnt/ramdisk/vllm/.vllm_installed"
	if _, err := os.Stat(sentinelPath); err == nil {
		verifyCUDARuntime()
		return nil
	}
	if _, err := os.Stat("/mnt/ramdisk/vllm/bin/vllm"); err == nil {
		verifyCUDARuntime()
		return nil
	}

	uvPath, err := exec.LookPath("uv")
	if err != nil {
		uvPath = "/usr/bin/uv"
	}
	if _, err := os.Stat(uvPath); err != nil {
		return fmt.Errorf("uv package installer not found at %s: vLLM runtime cannot be provisioned", uvPath)
	}

	system.Log("Provisioning vLLM Python runtime environment into /mnt/ramdisk/vllm...")
	_ = os.MkdirAll("/mnt/ramdisk/vllm", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/tmp", 01777)
	_ = os.Chmod("/mnt/ramdisk/tmp", 01777)
	_ = os.MkdirAll("/mnt/ramdisk/cache", 0755)
	_ = os.MkdirAll("/mnt/ramdisk/home", 0755)
	if os.Getuid() == 0 {
		_ = os.Chown("/mnt/ramdisk/vllm", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/tmp", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/cache", 1000, 1000)
		_ = os.Chown("/mnt/ramdisk/home", 1000, 1000)
	}

	// Step 1: Create virtual environment
	cmdVenv := exec.Command(uvPath, "venv", "/mnt/ramdisk/vllm", "--python", "/usr/bin/python3")
	cmdVenv.Env = []string{
		"PATH=/usr/bin:/bin",
		"HOME=/mnt/ramdisk/home",
		"TMPDIR=/mnt/ramdisk/tmp",
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
	}
	if out, err := cmdVenv.CombinedOutput(); err != nil {
		system.LogError("Failed to create venv: %v (%s)", err, string(out))
		_ = os.RemoveAll("/mnt/ramdisk/vllm")
		return fmt.Errorf("failed to create vLLM venv: %w", err)
	}

	// Step 2: Install pinned requirements using uv with hash-verified CUDA 12.4 PyTorch backend
	lockPath := "/etc/cevell/vllm/requirements.lock.txt"
	reqPath := "/etc/cevell/vllm/requirements.txt"
	installFile := lockPath
	if _, err := os.Stat(lockPath); err != nil {
		// Fallback to unlocked requirements if lockfile is missing (dev builds)
		system.Log("WARNING: Hash-locked requirements file not found at %s, falling back to %s", lockPath, reqPath)
		installFile = reqPath
	}
	if _, err := os.Stat(installFile); err != nil {
		return fmt.Errorf("vLLM requirements file not found at %s: cannot provision runtime", installFile)
	}
	pipArgs := []string{
		"pip", "install",
		"--python", "/mnt/ramdisk/vllm/bin/python3",
		"--torch-backend", "cu124",
		"--no-cache",
	}
	if installFile == lockPath {
		pipArgs = append(pipArgs, "--require-hashes")
	}
	pipArgs = append(pipArgs, "-r", installFile)

	system.Log("Installing GPU-locked vLLM packages with CUDA 12.4 support into /mnt/ramdisk/vllm...")
	cmdPip := exec.Command(uvPath, pipArgs...)
	cmdPip.Env = []string{
		"PATH=/mnt/ramdisk/vllm/bin:/usr/local/cuda/bin:/usr/bin:/bin:/sbin:/usr/sbin",
		"HOME=/mnt/ramdisk/home",
		"TMPDIR=/mnt/ramdisk/tmp",
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"VLLM_TARGET_DEVICE=cuda",
		"CUDA_DEVICE_ORDER=PCI_BUS_ID",
		"NVIDIA_VISIBLE_DEVICES=all",
		"NVIDIA_DRIVER_CAPABILITIES=compute,utility",
		"LD_LIBRARY_PATH=/mnt/ramdisk/vllm/lib:/mnt/ramdisk/vllm/lib64:/usr/lib/x86_64-linux-gnu:/usr/lib64:/lib64:/lib:/usr/local/cuda/lib64:/usr/local/cuda/lib",
	}
	out, err := cmdPip.CombinedOutput()
	if err != nil {
		system.LogError("Failed to install vLLM packages: %v (output: %s)", err, string(out))
		_ = os.RemoveAll("/mnt/ramdisk/vllm")
		return fmt.Errorf("failed to install vLLM packages: %w (output: %s)", err, string(out))
	}
	system.Log("vLLM package installation output:\n%s", string(out))

	_ = os.WriteFile(sentinelPath, []byte("ready\n"), 0644)
	system.Log("vLLM Python runtime successfully provisioned in /mnt/ramdisk/vllm.")

	verifyCUDARuntime()
	return nil
}

func verifyCUDARuntime() {
	pyPath := "/mnt/ramdisk/vllm/bin/python3"
	if _, err := os.Stat(pyPath); err != nil {
		if p, err := exec.LookPath("python3"); err == nil {
			pyPath = p
		} else {
			return
		}
	}
	checkCmd := exec.Command(pyPath, "-c", "import torch; print(f'CUDA available: {torch.cuda.is_available()}, devices: {torch.cuda.device_count()}, device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"None\"}')")
	checkCmd.Env = []string{
		"PATH=/mnt/ramdisk/vllm/bin:/usr/local/cuda/bin:/usr/bin:/usr/sbin:/bin:/sbin",
		"HOME=/mnt/ramdisk/home",
		"TMPDIR=/mnt/ramdisk/tmp",
		"VLLM_TARGET_DEVICE=cuda",
		"CUDA_DEVICE_ORDER=PCI_BUS_ID",
		"NVIDIA_VISIBLE_DEVICES=all",
		"NVIDIA_DRIVER_CAPABILITIES=compute,utility",
		"LD_LIBRARY_PATH=/mnt/ramdisk/vllm/lib:/mnt/ramdisk/vllm/lib64:/usr/lib/x86_64-linux-gnu:/usr/lib64:/lib64:/lib:/usr/local/cuda/lib64:/usr/local/cuda/lib",
	}
	if out, err := checkCmd.CombinedOutput(); err == nil {
		system.Log("vLLM CUDA discovery probe: %s", strings.TrimSpace(string(out)))
	} else {
		system.Log("vLLM CUDA discovery probe notice: %v (output: %s)", err, strings.TrimSpace(string(out)))
	}
}

// loadCPUModel launches llama-server with CPU vector optimization.
func (s *Supervisor) loadCPUModel(ctx context.Context, spec ModelSpec) error {
	s.mu.Lock()
	s.backendType = "llama.cpp"
	topo := s.topo
	s.mu.Unlock()

	if spec.Threads <= 0 {
		spec.Threads = topo.CPUCores
	}

	system.Log("Provisioning model %s on CPU inference engine (CPUs: %d, AVX512: %v, AVX2: %v)...",
		spec.Model, topo.CPUCores, topo.HasAVX512, topo.HasAVX2)

	var args []string
	args = append(args,
		"--host", "127.0.0.1",
		"--port", fmt.Sprintf("%d", s.port),
		"-c", fmt.Sprintf("%d", spec.ContextSize),
		"-t", fmt.Sprintf("%d", spec.Threads),
	)

	// Check if local model file exists
	if _, err := os.Stat(spec.Model); err == nil {
		args = append(args, "-m", spec.Model)
	} else if localGGUF := findLocalGGUF(spec.Model); localGGUF != "" {
		args = append(args, "-m", localGGUF)
	} else {
		// Hugging Face Repo
		if spec.HFFile != "" {
			args = append(args, "--hf-repo", spec.Model, "--hf-file", spec.HFFile)
		} else if strings.Contains(strings.ToLower(spec.Model), "0.5b") || strings.Contains(strings.ToLower(spec.Model), "0_5b") {
			args = append(args, "--hf-repo", spec.Model, "--hf-file", "qwen2.5-0.5b-instruct-q4_k_m.gguf")
		} else {
			args = append(args, "--hf-repo", spec.Model)
		}
	}

	if topo.HasGPU {
		gpuLayers := spec.GPULayers
		if gpuLayers <= 0 {
			gpuLayers = 99
		}
		args = append(args, "-ngl", fmt.Sprintf("%d", gpuLayers))
	}

	binPath := findLlamaServerBinary()
	system.Log("Launching %s %s", binPath, strings.Join(args, " "))

	cmd := exec.Command(binPath, args...)
	configureSandboxProcAttr(cmd)
	cmd.Env = []string{
		"PATH=/usr/bin:/usr/sbin:/bin:/sbin",
		"HOME=/mnt/ramdisk/home",
		"LLAMA_CACHE=/mnt/ramdisk/cache",
		"HF_HOME=/mnt/ramdisk/cache",
		"TMPDIR=/tmp",
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
	}
	if spec.HFToken != "" {
		cmd.Env = append(cmd.Env,
			"HF_TOKEN="+spec.HFToken,
			"HUGGING_FACE_HUB_TOKEN="+spec.HFToken,
		)
	}

	return s.runEngineProcess(ctx, cmd, "[llama-server]")
}

// runEngineProcess starts the command and monitors health with fast-fail exit detection.
func (s *Supervisor) runEngineProcess(ctx context.Context, cmd *exec.Cmd, logPrefix string) error {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start inference engine: %w", err)
	}
	s.mu.Lock()
	s.currentCmd = cmd
	s.mu.Unlock()

	// Track recent logs for fast diagnostic reporting if process exits prematurely
	var logBufMu sync.Mutex
	var recentLogs []string
	appendLog := func(line string) {
		logBufMu.Lock()
		defer logBufMu.Unlock()
		if len(recentLogs) >= 30 {
			recentLogs = recentLogs[1:]
		}
		recentLogs = append(recentLogs, line)
	}

	// Stream stdout & stderr concurrently into system log and buffer to prevent pipe deadlocks (INF-01)
	drainPipe := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			text := scanner.Text()
			appendLog(text)
			if system.IsConsoleDebugActive() {
				system.Log("%s %s", logPrefix, text)
			}
		}
	}
	go drainPipe(stdoutPipe)
	go drainPipe(stderrPipe)

	exitChan := make(chan error, 1)
	go func() {
		exitErr := cmd.Wait()
		exitChan <- exitErr
	}()

	// Poll health endpoint until ready or fast-fail if process exits prematurely
	readyChan := make(chan error, 1)
	pollCtx, pollCancel := context.WithCancel(ctx)
	defer pollCancel()

	go func() {
		endpoint := fmt.Sprintf("http://127.0.0.1:%d/health", s.port)
		client := &http.Client{Timeout: 2 * time.Second}
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				resp, err := client.Get(endpoint)
				if err == nil {
					if resp.StatusCode == http.StatusOK {
						var statusMap map[string]any
						_ = json.NewDecoder(resp.Body).Decode(&statusMap)
						statusVal, _ := statusMap["status"].(string)
						if statusVal == "ok" || statusVal == "ready" || statusVal == "" {
							resp.Body.Close()
							readyChan <- nil
							return
						}
					}
					resp.Body.Close()
				}
			}
		}
	}()

	timeoutTimer := time.NewTimer(600 * time.Second)
	defer timeoutTimer.Stop()

	select {
	case <-ctx.Done():
		_ = killProcessGroup(cmd)
		<-exitChan
		s.mu.Lock()
		if s.livenessCancel != nil {
			s.livenessCancel()
			s.livenessCancel = nil
		}
		if s.currentCmd == cmd {
			s.currentCmd = nil
			s.engineReady = false
		}
		s.mu.Unlock()
		return ctx.Err()
	case exitErr := <-exitChan:
		s.mu.Lock()
		if s.livenessCancel != nil {
			s.livenessCancel()
			s.livenessCancel = nil
		}
		if s.currentCmd == cmd {
			s.currentCmd = nil
			s.engineReady = false
		}
		s.mu.Unlock()
		logBufMu.Lock()
		tailOutput := strings.Join(recentLogs, "\n")
		logBufMu.Unlock()
		return fmt.Errorf("inference process exited prematurely (%v): %s", exitErr, tailOutput)
	case <-readyChan:
		liveCtx, liveCancel := context.WithCancel(context.Background())
		s.mu.Lock()
		if s.livenessCancel != nil {
			s.livenessCancel()
		}
		s.livenessCancel = liveCancel
		s.engineReady = true
		modelName := s.currentModel
		s.mu.Unlock()
		s.RecordActivity()
		system.Log("Inference engine ready for model %s on port %d!", modelName, s.port)

		// Start continuous post-readiness liveness prober
		go s.startLivenessProber(liveCtx)

		// Monitor process exit in background to reset readiness if crashed
		go func() {
			exitErr := <-exitChan
			s.mu.Lock()
			if s.livenessCancel != nil {
				s.livenessCancel()
				s.livenessCancel = nil
			}
			if s.currentCmd == cmd {
				s.engineReady = false
				s.currentCmd = nil
			}
			s.mu.Unlock()
			if exitErr != nil {
				system.LogError("Inference engine process terminated: %v", exitErr)
			}
		}()
		return nil
	case <-timeoutTimer.C:
		_ = killProcessGroup(cmd)
		<-exitChan
		s.mu.Lock()
		if s.livenessCancel != nil {
			s.livenessCancel()
			s.livenessCancel = nil
		}
		if s.currentCmd == cmd {
			s.currentCmd = nil
			s.engineReady = false
		}
		s.mu.Unlock()
		return fmt.Errorf("timed out waiting for inference backend on port %d", s.port)
	}
}

func findGPUInferenceBinary() (string, []string, string) {
	if _, err := os.Stat("/mnt/ramdisk/vllm/bin/vllm"); err == nil {
		return "/mnt/ramdisk/vllm/bin/vllm", []string{"serve"}, "vllm"
	}
	if _, err := os.Stat("/mnt/ramdisk/vllm/bin/python3"); err == nil {
		return "/mnt/ramdisk/vllm/bin/python3", []string{"-m", "vllm.entrypoints.openai.api_server", "--model"}, "vllm"
	}
	return "", nil, ""
}

func findLlamaServerBinary() string {
	candidates := []string{
		"/usr/bin/llama-server",
		"/bin/llama-server",
		"/usr/local/bin/llama-server",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("llama-server"); err == nil {
		return p
	}
	return "llama-server"
}

func findLocalGGUF(modelName string) string {
	cleanName := filepath.Clean(modelName)
	if strings.HasPrefix(cleanName, "/") {
		if _, err := os.Stat(cleanName); err == nil {
			return cleanName
		}
	}
	candidates := []string{
		filepath.Join("/opt/models", cleanName),
		filepath.Join("/mnt/ramdisk/models", cleanName),
	}
	if cleanName == "model.gguf" || cleanName == "" {
		candidates = append(candidates, "/opt/models/model.gguf", "/mnt/ramdisk/models/model.gguf")
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// configureSandboxProcAttr configures Linux privilege separation and namespace isolation
// for inference engines when running as root in production CVMs.
func configureSandboxProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if os.Getuid() == 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid:    1000,
			Gid:    1000,
			Groups: []uint32{998},
		}
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWIPC
	}
}

