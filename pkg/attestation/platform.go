package attestation

import (
	"fmt"
	"os"
)

const (
	PlatformSEVSNP   = "amd-sev-snp"
	PlatformTDX      = "intel-tdx"
	PlatformNVIDIACC = "nvidia-cc"
	PlatformNone     = "none"
)

// DetectPlatform dynamically returns the active CPU enclave platform string.
func DetectPlatform() string {
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		return PlatformSEVSNP
	}
	if IsIntelTDXEnvironment() {
		return PlatformTDX
	}
	return PlatformNone
}

// FetchHardwareReport queries the active hardware enclave (AMD SEV-SNP, Intel TDX, or Linux TSM).
func FetchHardwareReport(data [64]byte) ([]byte, string, string, error) {
	// 1. Check AMD SEV-SNP via /dev/sev-guest
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		report, chain, platform, err := FetchAMDReport(data)
		if err == nil && len(report) > 0 {
			return report, chain, platform, nil
		}
	}

	// 2. Check Intel TDX via /dev/tdx_guest or Linux ConfigFS TSM
	if quote, chain, platform, err := FetchTDXReport(data); err == nil && len(quote) > 0 {
		return quote, chain, platform, nil
	}

	// 3. Environment detection fallback (for simulated / dev CVM environments)
	if IsIntelTDXEnvironment() {
		return nil, "", PlatformTDX, fmt.Errorf("Intel TDX hardware active (guest driver initializing)")
	}

	return nil, "", PlatformNone, fmt.Errorf("Confidential computing hardware device unavailable (neither SEV-SNP nor TDX detected)")
}
