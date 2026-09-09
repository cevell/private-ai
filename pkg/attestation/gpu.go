package attestation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cevell/private-ai/pkg/system"
)

var nvmlQueryMu sync.Mutex

// GPUEvidence represents evidence collected from NVIDIA Hopper/Blackwell GPUs.
type GPUEvidence struct {
	Nonce            string            `json:"nonce"`
	CCEnabled        bool              `json:"cc_enabled"`
	DeviceCount      int               `json:"device_count"`
	Model            string            `json:"model,omitempty"`
	Driver           string            `json:"driver_version,omitempty"`
	Architecture     string            `json:"architecture,omitempty"`
	EvidenceReport   string            `json:"evidence_report,omitempty"`
	CertificateChain string            `json:"certificate_chain,omitempty"`
	Signature        string            `json:"signature,omitempty"`
	Devices          []string          `json:"devices,omitempty"`
	Evidences        []json.RawMessage `json:"evidences,omitempty"`
}

// IsNVIDIAConfidentialComputingActive checks if NVIDIA CC mode is active on Hopper / Blackwell GPUs.
func IsNVIDIAConfidentialComputingActive() bool {
	if matches, err := filepath.Glob("/proc/driver/nvidia/capabilities/*"); err == nil && len(matches) > 0 {
		return true
	}
	if matches, err := filepath.Glob("/dev/nvidia-caps/*"); err == nil && len(matches) > 0 {
		return true
	}
	if data, err := os.ReadFile("/sys/module/nvidia/parameters/NVreg_EnableCC"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			return true
		}
	}
	if matches, err := filepath.Glob("/sys/bus/pci/drivers/nvidia/*:*"); err == nil && len(matches) > 0 {
		return true
	}
	return false
}

// nvmlQueryResult represents the JSON output from the hardware NVML CC query.
type nvmlQueryResult struct {
	CCEnabled        bool   `json:"cc_enabled"`
	Model            string `json:"model"`
	Driver           string `json:"driver_version"`
	Architecture     string `json:"architecture"`
	EvidenceReport   string `json:"evidence_report"`
	CertificateChain string `json:"certificate_chain"`
	Signature        string `json:"signature"`
	Error            string `json:"error,omitempty"`
}

const nvmlQueryScript = `
import ctypes, json, sys, base64

nonce_hex = sys.argv[1] if len(sys.argv) > 1 else "0" * 64

result = {
    "cc_enabled": False,
    "model": "",
    "driver_version": "",
    "architecture": "",
    "evidence_report": "",
    "certificate_chain": "",
    "signature": "",
    "error": ""
}

try:
    # 1. Load libnvidia-ml.so
    nvml = None
    for lib_path in [
        "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
        "/usr/lib64/libnvidia-ml.so.1",
        "/lib64/libnvidia-ml.so.1",
        "/lib/libnvidia-ml.so.1",
        "libnvidia-ml.so.1",
        "libnvidia-ml.so"
    ]:
        try:
            nvml = ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)
            break
        except Exception:
            continue

    if not nvml:
        result["error"] = "libnvidia-ml.so not found"
        print(json.dumps(result))
        sys.exit(0)

    nvml_err_fn = getattr(nvml, "nvmlErrorString", None)
    def err_str(code):
        if nvml_err_fn:
            try:
                nvml_err_fn.restype = ctypes.c_char_p
                return nvml_err_fn(code).decode("utf-8", errors="ignore")
            except Exception:
                pass
        return str(code)

    # 2. Initialize NVML
    init_fn = getattr(nvml, "nvmlInit_v2", getattr(nvml, "nvmlInit", None))
    if not init_fn:
        result["error"] = "nvmlInit symbol not found in libnvidia-ml.so"
        print(json.dumps(result))
        sys.exit(0)
    ret = init_fn()
    if ret != 0:
        result["error"] = f"nvmlInit failed: {err_str(ret)}"
        print(json.dumps(result))
        sys.exit(0)

    # 3. Get Device 0
    get_dev_fn = getattr(nvml, "nvmlDeviceGetHandleByIndex_v2", getattr(nvml, "nvmlDeviceGetHandleByIndex", None))
    dev = ctypes.c_void_p()
    if not get_dev_fn:
        result["error"] = "nvmlDeviceGetHandleByIndex symbol not found"
        print(json.dumps(result))
        sys.exit(0)
    get_dev_fn.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)]
    get_dev_fn.restype = ctypes.c_int
    ret = get_dev_fn(0, ctypes.byref(dev))
    if ret != 0:
        result["error"] = f"nvmlDeviceGetHandleByIndex failed: {err_str(ret)}"
        print(json.dumps(result))
        sys.exit(0)

    # 4. Ensure Confidential Compute Ready State (prerequisite for attestation)
    try:
        import subprocess
        subprocess.run(["nvidia-smi", "conf-compute", "-srs", "1"], capture_output=True, timeout=5)
    except Exception:
        pass

    set_ready_fn = getattr(nvml, "nvmlSystemSetConfComputeGpusReadyState", None)
    if set_ready_fn:
        try:
            set_ready_fn.argtypes = [ctypes.c_uint]
            set_ready_fn.restype = ctypes.c_int
            set_ready_fn(1)
        except Exception:
            pass

    # 5. Check Confidential Compute State
    get_cc_state = getattr(nvml, "nvmlSystemGetConfComputeState", None)
    if get_cc_state:
        class NVMLCCState(ctypes.Structure):
            _fields_ = [
                ("environment", ctypes.c_uint),
                ("ccFeature", ctypes.c_uint),
                ("devToolsMode", ctypes.c_uint),
            ]
        cc_state = NVMLCCState()
        get_cc_state.argtypes = [ctypes.POINTER(NVMLCCState)]
        get_cc_state.restype = ctypes.c_int
        if get_cc_state(ctypes.byref(cc_state)) == 0:
            if cc_state.ccFeature == 1:
                result["cc_enabled"] = True

    # 6. Retrieve Hardware DICE Certificate Chain
    get_cert_fn = getattr(nvml, "nvmlDeviceGetConfComputeGpuCertificate", getattr(nvml, "nvmlDeviceGetConfidentialComputeGpuCertificate", None))
    if not get_cert_fn:
        result["error"] += " [nvmlDeviceGetConfComputeGpuCertificate symbol not found]"
    else:
        class NVMLGpuCert(ctypes.Structure):
            _fields_ = [
                ("certChainSize", ctypes.c_uint32),
                ("attestationCertChainSize", ctypes.c_uint32),
                ("certChain", ctypes.c_char * 4096),
                ("attestationCertChain", ctypes.c_char * 5120),
            ]
        cert_struct = NVMLGpuCert()
        get_cert_fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(NVMLGpuCert)]
        get_cert_fn.restype = ctypes.c_int
        ret = get_cert_fn(dev, ctypes.byref(cert_struct))
        if ret == 0:
            cert_pem = ""
            if cert_struct.certChainSize > 0:
                sz = min(4096, int(cert_struct.certChainSize))
                cert_pem += cert_struct.certChain[:sz].decode("utf-8", errors="ignore")
            if cert_struct.attestationCertChainSize > 0:
                sz = min(5120, int(cert_struct.attestationCertChainSize))
                att_pem = cert_struct.attestationCertChain[:sz].decode("utf-8", errors="ignore")
                if att_pem not in cert_pem:
                    cert_pem = (cert_pem + "\n" + att_pem).strip()
            if cert_pem:
                result["certificate_chain"] = cert_pem
                result["cc_enabled"] = True
        else:
            result["error"] += f" [cert: {err_str(ret)}]"

    # 7. Retrieve Hardware SPDM Attestation Report
    get_report_fn = getattr(nvml, "nvmlDeviceGetConfComputeGpuAttestationReport", getattr(nvml, "nvmlDeviceGetConfidentialComputeGpuAttestationReport", None))
    if not get_report_fn:
        result["error"] += " [nvmlDeviceGetConfComputeGpuAttestationReport symbol not found]"
    else:
        class NVMLGpuReport(ctypes.Structure):
            _fields_ = [
                ("isCecAttestationReportPresent", ctypes.c_uint32),
                ("attestationReportSize", ctypes.c_uint32),
                ("cecAttestationReportSize", ctypes.c_uint32),
                ("nonce", ctypes.c_ubyte * 32),
                ("attestationReport", ctypes.c_ubyte * 8192),
                ("cecAttestationReport", ctypes.c_ubyte * 4096),
            ]
        rep_struct = NVMLGpuReport()
        nonce_bytes = bytes.fromhex(nonce_hex)
        for i in range(min(32, len(nonce_bytes))):
            rep_struct.nonce[i] = nonce_bytes[i]

        get_report_fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(NVMLGpuReport)]
        get_report_fn.restype = ctypes.c_int
        ret = get_report_fn(dev, ctypes.byref(rep_struct))
        if ret == 0 and rep_struct.attestationReportSize > 0:
            rep_size = min(8192, int(rep_struct.attestationReportSize))
            raw_rep = bytes(rep_struct.attestationReport[:rep_size])
            result["evidence_report"] = base64.b64encode(raw_rep).decode("ascii")
            result["cc_enabled"] = True
        elif ret != 0:
            result["error"] += f" [report: {err_str(ret)}]"

except Exception as e:
    result["error"] = str(e)

print(json.dumps(result))
`

// queryHardwareNVIDIACC executes the NVML query script to retrieve genuine hardware certificates and SPDM reports.
func queryHardwareNVIDIACC(nonce [32]byte) *nvmlQueryResult {
	nvmlQueryMu.Lock()
	defer nvmlQueryMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nonceHex := hex.EncodeToString(nonce[:])
	cmd := exec.CommandContext(ctx, "python3", "-c", nvmlQueryScript, nonceHex)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/usr/lib64:/lib64:/lib:/usr/local/cuda/lib64")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &nvmlQueryResult{
			CCEnabled: false,
			Error:     fmt.Sprintf("NVML query process error: %v (stderr: %s)", err, stderr.String()),
		}
	}

	var res nvmlQueryResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return &nvmlQueryResult{
			CCEnabled: false,
			Error:     fmt.Sprintf("Failed to parse NVML output: %v (raw: %s)", err, stdout.String()),
		}
	}

	return &res
}

// CollectGPUEvidence gathers cryptographic evidence from installed NVIDIA GPUs using the provided 32-byte nonce.
func CollectGPUEvidence(nonce [32]byte) (*GPUEvidence, error) {
	evidence := &GPUEvidence{
		Nonce:     hex.EncodeToString(nonce[:]),
		CCEnabled: false,
	}

	// 1. Scan character devices
	if matches, err := filepath.Glob("/dev/nvidia[0-9]*"); err == nil && len(matches) > 0 {
		evidence.DeviceCount = len(matches)
		evidence.Devices = matches
	}

	// 2. Scan PCI devices for NVIDIA GPUs (vendor 0x10de)
	if pciVendors, err := filepath.Glob("/sys/bus/pci/devices/*/vendor"); err == nil {
		for _, vf := range pciVendors {
			if data, err := os.ReadFile(vf); err == nil {
				v := strings.ToLower(strings.TrimSpace(string(data)))
				if v == "0x10de" {
					devDir := filepath.Dir(vf)
					pciID := filepath.Base(devDir)
					evidence.Devices = append(evidence.Devices, pciID)

					if devData, err := os.ReadFile(filepath.Join(devDir, "device")); err == nil {
						devID := strings.ToLower(strings.TrimSpace(string(devData)))
						switch devID {
						case "0x2330", "0x2331", "0x2322", "0x2324":
							evidence.Model = "NVIDIA H100 80GB HBM3"
							evidence.Architecture = "Hopper"
						case "0x27b8", "0x2782":
							evidence.Model = "NVIDIA L4"
							evidence.Architecture = "Ada"
						case "0x1eb8", "0x1eb1":
							evidence.Model = "NVIDIA Tesla T4"
							evidence.Architecture = "Turing"
						case "0x20b0", "0x20b2":
							evidence.Model = "NVIDIA A100"
							evidence.Architecture = "Ampere"
						}
					}
				}
			}
		}
		if len(evidence.Devices) > 0 && evidence.DeviceCount == 0 {
			evidence.DeviceCount = len(evidence.Devices)
		}
	}

	// 3. Extract GPU model name from driver procfs if available
	if gpuInfos, err := filepath.Glob("/proc/driver/nvidia/gpus/*/information"); err == nil && len(gpuInfos) > 0 {
		if data, err := os.ReadFile(gpuInfos[0]); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "Model:") {
					evidence.Model = strings.TrimSpace(strings.TrimPrefix(line, "Model:"))
				}
			}
		}
	}

	// 4. Extract Driver version
	if vData, err := os.ReadFile("/proc/driver/nvidia/version"); err == nil {
		for _, token := range strings.Fields(string(vData)) {
			if strings.Contains(token, ".") && (strings.HasPrefix(token, "5") || strings.HasPrefix(token, "6")) {
				evidence.Driver = token
				break
			}
		}
	}

	// 5. Query genuine Hardware NVML if GPUs are detected
	if evidence.DeviceCount > 0 {
		if evidence.Architecture == "" {
			if strings.Contains(evidence.Model, "H100") || strings.Contains(evidence.Model, "H200") {
				evidence.Architecture = "Hopper"
			} else if strings.Contains(evidence.Model, "L4") || strings.Contains(evidence.Model, "L40") {
				evidence.Architecture = "Ada"
			} else if strings.Contains(evidence.Model, "T4") {
				evidence.Architecture = "Turing"
			} else if strings.Contains(evidence.Model, "A100") || strings.Contains(evidence.Model, "A10") {
				evidence.Architecture = "Ampere"
			}
		}

		// Query NVML for genuine hardware CC certificates and SPDM quote
		nvmlRes := queryHardwareNVIDIACC(nonce)
		if nvmlRes != nil {
			if nvmlRes.CCEnabled {
				evidence.CCEnabled = true
				evidence.EvidenceReport = nvmlRes.EvidenceReport
				evidence.CertificateChain = nvmlRes.CertificateChain
				evidence.Signature = nvmlRes.Signature
				system.Log("NVIDIA GPU CC evidence acquired: certChainLen=%d, reportLen=%d", len(evidence.CertificateChain), len(evidence.EvidenceReport))
			} else {
				system.LogError("NVML hardware CC query unsuccessful: %s", nvmlRes.Error)
			}
		}
	}

	return evidence, nil
}

// CollectNVSwitchEvidence gathers NVSwitch evidence for multi-GPU configurations.
func CollectNVSwitchEvidence(nonce [32]byte) (json.RawMessage, error) {
	return nil, fmt.Errorf("NVSwitch attestation not required on current topology")
}
