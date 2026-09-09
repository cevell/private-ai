package inference

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cevell/private-ai/pkg/hardware"
)

// ModelArchitectureMeta describes the architectural parameters of a model relevant to KV-cache sizing.
type ModelArchitectureMeta struct {
	ModelID            string  `json:"model_id"`
	NumLayers          int     `json:"num_layers"`
	NumKVHeads         int     `json:"num_kv_heads"`
	HeadDim            int     `json:"head_dim"`
	ModelNativeMax     int     `json:"model_native_max"`
	ParamCountBillions float64 `json:"param_count_billions"`
	BytesPerParam      float64 `json:"bytes_per_param"` // 2.0 for FP16/BF16, 0.55 for AWQ/INT4
	IsQuantized        bool    `json:"is_quantized"`
}

type hfConfigJSON struct {
	HiddenSize            int            `json:"hidden_size"`
	NumHiddenLayers       int            `json:"num_hidden_layers"`
	NumAttentionHeads     int            `json:"num_attention_heads"`
	NumKeyValueHeads      int            `json:"num_key_value_heads"`
	MaxPositionEmbeddings int            `json:"max_position_embeddings"`
	SeqLength             int            `json:"seq_length"`
	SlidingWindow         int            `json:"sliding_window"`
	TorchDtype            string         `json:"torch_dtype"`
	QuantizationConfig    map[string]any `json:"quantization_config"`
	RopeScaling           map[string]any `json:"rope_scaling"`
}

// InspectModelMetadata inspects local config files, fetches remote config.json from Hugging Face if online,
// or deduces architecture from open-weight model heuristics as a graceful fallback.
func InspectModelMetadata(modelIdentifier string, hfTokens ...string) ModelArchitectureMeta {
	meta := ModelArchitectureMeta{
		ModelID:            modelIdentifier,
		NumLayers:          32,
		NumKVHeads:         8,
		HeadDim:            128,
		ModelNativeMax:     4096,
		ParamCountBillions: 7.0,
		BytesPerParam:      2.0, // Default FP16 / BF16
		IsQuantized:        false,
	}

	// 1. Check for local config.json in standard cache and model directories
	candidates := []string{
		modelIdentifier,
		filepath.Join(modelIdentifier, "config.json"),
		filepath.Join("/opt/models", modelIdentifier, "config.json"),
		filepath.Join("/mnt/ramdisk/models", modelIdentifier, "config.json"),
	}

	// Check huggingface cache paths
	hfCacheRepo := "models--" + strings.ReplaceAll(modelIdentifier, "/", "--")
	if snapshots, err := filepath.Glob(filepath.Join("/mnt/ramdisk/cache", hfCacheRepo, "snapshots", "*", "config.json")); err == nil && len(snapshots) > 0 {
		candidates = append(candidates, snapshots[0])
	}

	foundLocal := false
	for _, cand := range candidates {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			if data, err := os.ReadFile(cand); err == nil {
				var cfg hfConfigJSON
				if err := json.Unmarshal(data, &cfg); err == nil {
					applyHFConfigToMeta(&cfg, &meta)
					foundLocal = true
					break
				}
			}
		}
	}

	// 2. If not found locally and appears to be a remote Hugging Face model ID (Org/Repo),
	// attempt a fast, resilient HTTP query to fetch the authoritative config.json.
	if !foundLocal && strings.Contains(modelIdentifier, "/") && !filepath.IsAbs(modelIdentifier) && !strings.HasPrefix(modelIdentifier, ".") {
		token := ""
		if len(hfTokens) > 0 {
			token = hfTokens[0]
		}
		if remoteCfg := fetchRemoteHFConfig(modelIdentifier, token); remoteCfg != nil {
			applyHFConfigToMeta(remoteCfg, &meta)
			foundLocal = true
		}
	}

	// Architectural and parameter deduction from model name tokens
	lower := strings.ToLower(modelIdentifier)

	// Check quantization hints in model name
	if strings.Contains(lower, "awq") || strings.Contains(lower, "gptq") || strings.Contains(lower, "int4") || strings.Contains(lower, "q4") {
		meta.IsQuantized = true
		meta.BytesPerParam = 0.55
	} else if strings.Contains(lower, "int8") || strings.Contains(lower, "q8") {
		meta.IsQuantized = true
		meta.BytesPerParam = 1.05
	}

	// Deduce parameter count
	switch {
	case strings.Contains(lower, "0.5b"):
		meta.ParamCountBillions = 0.5
		meta.NumLayers = 24
		meta.NumKVHeads = 2
		meta.HeadDim = 64
	case strings.Contains(lower, "1.5b"), strings.Contains(lower, "1b"):
		meta.ParamCountBillions = 1.5
		meta.NumLayers = 28
		meta.NumKVHeads = 2
		meta.HeadDim = 128
	case strings.Contains(lower, "3b"):
		meta.ParamCountBillions = 3.0
		meta.NumLayers = 36
		meta.NumKVHeads = 2
		meta.HeadDim = 128
	case strings.Contains(lower, "7b"), strings.Contains(lower, "8b"):
		meta.ParamCountBillions = 7.5
		meta.NumLayers = 32
		meta.NumKVHeads = 8
		meta.HeadDim = 128
	case strings.Contains(lower, "14b"):
		meta.ParamCountBillions = 14.7
		meta.NumLayers = 48
		meta.NumKVHeads = 8
		meta.HeadDim = 128
	case strings.Contains(lower, "27b"), strings.Contains(lower, "32b"):
		meta.ParamCountBillions = 32.0
		meta.NumLayers = 64
		meta.NumKVHeads = 8
		meta.HeadDim = 128
	case strings.Contains(lower, "70b"), strings.Contains(lower, "72b"):
		meta.ParamCountBillions = 72.0
		meta.NumLayers = 80
		meta.NumKVHeads = 8
		meta.HeadDim = 128
	}

	// Model family native context lengths
	if meta.ModelNativeMax <= 4096 {
		switch {
		case strings.Contains(lower, "qwen2.5"), strings.Contains(lower, "qwen2"):
			if strings.Contains(lower, "0.5b") {
				meta.ModelNativeMax = 32768
			} else {
				meta.ModelNativeMax = 131072 // 128k native
			}
		case strings.Contains(lower, "llama-3.1"), strings.Contains(lower, "llama-3.2"), strings.Contains(lower, "llama3.1"), strings.Contains(lower, "llama3.2"):
			meta.ModelNativeMax = 131072 // 128k native
		case strings.Contains(lower, "llama-3"), strings.Contains(lower, "llama3"):
			meta.ModelNativeMax = 8192 // LLaMA 3.0 8k
		case strings.Contains(lower, "mistral"), strings.Contains(lower, "mixtral"):
			meta.ModelNativeMax = 32768 // 32k native
		case strings.Contains(lower, "phi-3"):
			meta.ModelNativeMax = 131072 // 128k native
		case strings.Contains(lower, "gemma-2"):
			meta.ModelNativeMax = 8192
		}
	}

	return meta
}

// CalculateMaxViableContext calculates the maximum safe context window supported by both model architecture and hardware.
func CalculateMaxViableContext(meta ModelArchitectureMeta, topo hardware.TopologyReport) (int, error) {
	// Sanitize architectural parameters to prevent division by zero or negative values
	if meta.NumLayers <= 0 {
		meta.NumLayers = 32
	}
	if meta.NumKVHeads <= 0 {
		meta.NumKVHeads = 8
	}
	if meta.HeadDim <= 0 {
		meta.HeadDim = 128
	}
	if meta.ParamCountBillions <= 0 {
		meta.ParamCountBillions = 7.0
	}
	if meta.BytesPerParam <= 0 {
		meta.BytesPerParam = 2.0
	}

	// CPU mode evaluation
	if !topo.HasGPU || topo.GPUCount <= 0 {
		totalRAMMB := topo.RAMTotalMB
		if totalRAMMB <= 0 {
			totalRAMMB = 16384 // 16GB baseline
		}

		weightMB := int(meta.ParamCountBillions * meta.BytesPerParam * 1024)
		usableRAMMB := int(float64(totalRAMMB)*0.70) - weightMB - 1024 // 1GB OS headroom
		if usableRAMMB <= 0 {
			return 0, fmt.Errorf("insufficient system RAM: model weights (est. %.1f GB) exceed available memory (%.1f GB)",
				float64(weightMB)/1024, float64(totalRAMMB)/1024)
		}

		// CPU bytes per token estimate
		bytesPerToken := 2 * meta.NumLayers * meta.NumKVHeads * meta.HeadDim * 2
		maxTokens := (int64(usableRAMMB) * 1024 * 1024) / int64(bytesPerToken)
		return alignContextLength(int(maxTokens), meta.ModelNativeMax), nil
	}

	// GPU mode evaluation
	totalVRAMMB := topo.VRAMTotalMB
	if totalVRAMMB <= 0 {
		totalVRAMMB = topo.GPUCount * 16384 // 16GB per GPU baseline fallback
	}

	weightMB := int(meta.ParamCountBillions * meta.BytesPerParam * 1024)
	if weightMB > int(float64(totalVRAMMB)*0.92) {
		return 0, fmt.Errorf("insufficient GPU VRAM: model weights (est. %.1f GB) exceed available GPU memory (%.1f GB across %d GPU(s))",
			float64(weightMB)/1024, float64(totalVRAMMB)/1024, topo.GPUCount)
	}

	// Reserve 1.5GB workspace memory per GPU for activations, PyTorch workspace, and CUDA graphs
	workspaceMB := 1536 * topo.GPUCount
	usableVRAMMB := int(float64(totalVRAMMB)*0.90) - weightMB - workspaceMB
	if usableVRAMMB < 512 {
		usableVRAMMB = 512 // Minimal KV cache budget
	}

	tp := topo.GPUCount
	if tp <= 0 {
		tp = 1
	}

	kvHeadsPerTP := meta.NumKVHeads / tp
	if kvHeadsPerTP <= 0 {
		kvHeadsPerTP = 1
	}

	// PagedAttention KV Cache bytes per token in FP16 (2 bytes key + 2 bytes value)
	bytesPerToken := 2 * meta.NumLayers * kvHeadsPerTP * meta.HeadDim * 2

	// Target concurrency headroom = 2 concurrent streams
	concurrency := 2
	maxTokens := (int64(usableVRAMMB) * 1024 * 1024) / (int64(bytesPerToken) * int64(concurrency))

	return alignContextLength(int(maxTokens), meta.ModelNativeMax), nil
}

// alignContextLength clamps and snaps calculated tokens to standard 1024 or power-of-two boundaries.
func alignContextLength(hardwareMax, modelNativeMax int) int {
	ceiling := modelNativeMax
	if ceiling <= 0 {
		ceiling = 32768
	}

	target := hardwareMax
	if target > ceiling {
		target = ceiling
	}

	// Standard transformer context intervals
	standardBuckets := []int{2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144}

	selected := 2048
	for _, b := range standardBuckets {
		if b <= target {
			selected = b
		} else {
			break
		}
	}

	if target < 2048 {
		if target >= 1024 {
			return 1024
		}
		if target >= 512 {
			return 512
		}
		return 512
	}

	return selected
}

// FormatContextSize returns a human-readable token representation (e.g. 32K).
func FormatContextSize(tokens int) string {
	if tokens >= 1024 {
		return strconv.Itoa(tokens/1024) + "K"
	}
	return strconv.Itoa(tokens)
}

func applyHFConfigToMeta(cfg *hfConfigJSON, meta *ModelArchitectureMeta) {
	if cfg.NumHiddenLayers > 0 {
		meta.NumLayers = cfg.NumHiddenLayers
	}
	if cfg.NumAttentionHeads > 0 && cfg.HiddenSize > 0 {
		dim := cfg.HiddenSize / cfg.NumAttentionHeads
		if dim > 0 {
			meta.HeadDim = dim
		}
	}
	if cfg.NumKeyValueHeads > 0 {
		meta.NumKVHeads = cfg.NumKeyValueHeads
	} else if cfg.NumAttentionHeads > 0 {
		meta.NumKVHeads = cfg.NumAttentionHeads
	}
	if cfg.MaxPositionEmbeddings > 0 {
		meta.ModelNativeMax = cfg.MaxPositionEmbeddings
	} else if cfg.SeqLength > 0 {
		meta.ModelNativeMax = cfg.SeqLength
	}
	if len(cfg.QuantizationConfig) > 0 {
		meta.IsQuantized = true
		meta.BytesPerParam = 0.55
	}
}

func fetchRemoteHFConfig(repoID, token string) *hfConfigJSON {
	url := fmt.Sprintf("https://huggingface.co/%s/raw/main/config.json", repoID)
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("User-Agent", "cevell-cvm-node/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil
	}

	var cfg hfConfigJSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}

// EvaluateVRAMContextBudget determines whether the model's native context will fit in VRAM.
// Returns:
//   shouldClamp: true if VRAM is insufficient for native context and a safe clamped value must be passed to vLLM.
//                false if VRAM is sufficient, meaning no --max-model-len should be passed (vLLM auto-handles).
//   safeContext: the safe clamped context length (e.g. 8192, 4096) if shouldClamp is true; otherwise 0.
func EvaluateVRAMContextBudget(meta ModelArchitectureMeta, topo hardware.TopologyReport, requestedContext int) (bool, int) {
	// 1. If user explicitly requested a context length > 0, honor user intent:
	if requestedContext > 0 {
		return true, requestedContext
	}

	// 2. If GPU topology or VRAM is unknown or invalid, fail safe: don't pass any flag, let vLLM auto-handle!
	if !topo.HasGPU || topo.GPUCount <= 0 || topo.VRAMTotalMB <= 0 {
		return false, 0
	}

	// 3. If model metadata is unknown or invalid, fail safe: let vLLM auto-handle!
	if meta.ParamCountBillions <= 0 || meta.ModelNativeMax <= 0 {
		return false, 0
	}

	// 4. Calculate memory requirements:
	weightMB := int(meta.ParamCountBillions * meta.BytesPerParam * 1024)
	workspaceMB := 1536 * topo.GPUCount
	usableVRAMMB := int(float64(topo.VRAMTotalMB)*0.90) - workspaceMB

	// Remaining VRAM for KV cache
	remainingKVMB := usableVRAMMB - weightMB
	if remainingKVMB <= 0 {
		// Model weights alone fill or exceed VRAM. Clamp to minimal viable context to prevent immediate OOM
		return true, 2048
	}

	tp := topo.GPUCount
	if tp <= 0 {
		tp = 1
	}
	kvHeadsPerTP := meta.NumKVHeads / tp
	if kvHeadsPerTP <= 0 {
		kvHeadsPerTP = 1
	}
	headDim := meta.HeadDim
	if headDim <= 0 {
		headDim = 128
	}
	layers := meta.NumLayers
	if layers <= 0 {
		layers = 32
	}

	// Bytes per token in FP16 KV cache (2 bytes K + 2 bytes V)
	bytesPerToken := 2 * layers * kvHeadsPerTP * headDim * 2
	concurrency := 2

	// Memory needed for native max context
	requiredNativeKVMB := int((int64(bytesPerToken) * int64(meta.ModelNativeMax) * int64(concurrency)) / (1024 * 1024))

	// 5. DECISION: Will default context cause a crash?
	if remainingKVMB >= requiredNativeKVMB {
		// Plenty of VRAM! Do NOT pass --max-model-len, let vLLM use its native configuration!
		return false, 0
	}

	// VRAM is constrained! Native context would OOM. Clamp down to safe maximum.
	maxSafeTokens := (int64(remainingKVMB) * 1024 * 1024) / (int64(bytesPerToken) * int64(concurrency))
	clamped := alignContextLength(int(maxSafeTokens), meta.ModelNativeMax)
	return true, clamped
}
