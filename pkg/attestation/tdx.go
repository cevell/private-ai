package attestation

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var tsmReportMu sync.Mutex

// FetchTDXReport queries Intel TDX attestation quote via Linux ConfigFS TSM or /dev/tdx_guest device.
func FetchTDXReport(data [64]byte) ([]byte, string, string, error) {
	// 1. Try Linux ConfigFS TSM interface (/sys/kernel/config/tsm/report/)
	if quote, err := fetchTSMReport("tdx", data); err == nil && len(quote) > 0 {
		return quote, "", PlatformTDX, nil
	}

	// 2. Try generic TSM interface (accept any provider)
	if quote, err := fetchTSMReport("", data); err == nil && len(quote) > 0 {
		return quote, "", PlatformTDX, nil
	}

	// 3. Check if Intel TDX environment is present
	if IsIntelTDXEnvironment() {
		return nil, "", PlatformTDX, fmt.Errorf("Intel TDX hardware detected but ConfigFS TSM quote generation unavailable (local TDREPORT cannot be verified remotely without quoting enclave)")
	}

	return nil, "", PlatformNone, fmt.Errorf("Intel TDX hardware device unavailable")
}

// IsIntelTDXEnvironment checks CPU flags and sysfs for Intel TDX indicators.
func IsIntelTDXEnvironment() bool {
	if _, err := os.Stat("/sys/devices/virtual/misc/tdx_guest"); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/devices/virtual/misc/tdx-guest"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/tdx_guest"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/tdx-guest"); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/kernel/config/tsm/report"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := string(data)
		if strings.Contains(content, "GenuineIntel") && (strings.Contains(content, "tdx_guest") || strings.Contains(content, "tdx")) {
			return true
		}
	}
	return false
}

// fetchTSMReport queries /sys/kernel/config/tsm/report/ for Intel or AMD quote
func fetchTSMReport(expectedProvider string, data [64]byte) ([]byte, error) {
	tsmPath := "/sys/kernel/config/tsm/report"
	if _, err := os.Stat(tsmPath); err != nil {
		_ = os.MkdirAll("/sys/kernel/config", 0755)
		_ = exec.Command("mount", "-t", "configfs", "none", "/sys/kernel/config").Run()
	}
	if _, err := os.Stat(tsmPath); err != nil {
		return nil, err
	}

	tsmReportMu.Lock()
	defer tsmReportMu.Unlock()

	tag := expectedProvider
	if tag == "" {
		tag = "generic"
	}
	var randBytes [8]byte
	_, _ = rand.Read(randBytes[:])
	entryName := fmt.Sprintf("report_%s_%x_%x", tag, data[:8], randBytes)
	entryDir := filepath.Join(tsmPath, entryName)
	if err := os.Mkdir(entryDir, 0700); err != nil {
		return nil, err
	}
	defer os.Remove(entryDir)

	// Write inblob
	if err := os.WriteFile(filepath.Join(entryDir, "inblob"), data[:], 0600); err != nil {
		return nil, err
	}

	// Validate provider if specified
	if provBytes, err := os.ReadFile(filepath.Join(entryDir, "provider")); err == nil {
		prov := strings.ToLower(strings.TrimSpace(string(provBytes)))
		exp := strings.ToLower(strings.TrimSpace(expectedProvider))
		if exp != "" {
			if !strings.Contains(prov, exp) && !strings.Contains(exp, prov) {
				// Provider alias compatibility: "tdx" matches "tdx_guest" or "intel"
				if (exp == "tdx" || exp == "intel") && (strings.Contains(prov, "tdx") || strings.Contains(prov, "intel")) {
					// OK
				} else if (exp == "sev" || exp == "amd") && (strings.Contains(prov, "sev") || strings.Contains(prov, "amd")) {
					// OK
				} else {
					return nil, fmt.Errorf("provider mismatch: got %s, expected %s", prov, expectedProvider)
				}
			}
		}
	}

	// Read outblob (the raw quote)
	return os.ReadFile(filepath.Join(entryDir, "outblob"))
}

// queryTDXDevice issues TDX IOCTL to get TDX report / quote per <linux/tdx-guest.h>
func queryTDXDevice(devPath string, data [64]byte) ([]byte, error) {
	f, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// struct tdx_report_req per Linux kernel <linux/tdx-guest.h>:
	// __u8 reportdata[64];
	// __u8 tdreport[1024];
	type tdxReportReq struct {
		reportdata [64]byte
		tdreport   [1024]byte
	}

	var req tdxReportReq
	copy(req.reportdata[:], data[:])

	// TDX_CMD_GET_REPORT0 = _IOWR('T', 1, struct tdx_report_req)
	// Direction: _IOC_READ | _IOC_WRITE (3 << 30)
	// Size: sizeof(struct tdx_report_req) = 1088 (0x0440 << 16)
	// Type: 'T' (0x54 << 8)
	// NR: 1 -> 0xc4405401
	const TDX_CMD_GET_REPORT0 = 0xc4405401
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(TDX_CMD_GET_REPORT0), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return nil, errno
	}

	out := make([]byte, len(req.tdreport))
	copy(out, req.tdreport[:])
	return out, nil
}
