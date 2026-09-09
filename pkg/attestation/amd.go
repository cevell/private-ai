package attestation

import (
	"fmt"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
)

func resolveDefaultAMDChain() string {
	if IsCloudHypervisor() {
		return ResolveAMDVLEKChain()
	}
	return ResolveAMDVCEKChain()
}

// FetchAMDReport queries the local AMD PSP device or quote provider for an SEV-SNP hardware report.
func FetchAMDReport(data [64]byte) ([]byte, string, string, error) {
	if dev, devErr := sevclient.OpenDevice(); devErr == nil {
		rawRep, certs, extErr := sevclient.GetRawExtendedReport(dev, data)
		dev.Close()
		if extErr == nil && len(rawRep) >= sevabi.ReportSize {
			if len(rawRep) > sevabi.ReportSize {
				rawRep = rawRep[:sevabi.ReportSize]
			}
			chainPEM := ""
			if len(certs) > 0 {
				fullBuf := append(append([]byte{}, rawRep...), certs...)
				if attProto, protoErr := sevabi.ReportCertsToProto(fullBuf); protoErr == nil && attProto != nil {
					chainPEM = FormatCertificateChain(attProto.GetCertificateChain())
				}
			}
			if chainPEM == "" {
				chainPEM = resolveDefaultAMDChain()
			}
			return rawRep, chainPEM, PlatformSEVSNP, nil
		}
	}

	// Fallback to standard quote provider
	qp, err := sevclient.GetQuoteProvider()
	if err == nil {
		report, err := qp.GetRawQuote(data)
		if err == nil {
			if len(report) > sevabi.ReportSize {
				report = report[:sevabi.ReportSize]
			}
			return report, resolveDefaultAMDChain(), PlatformSEVSNP, nil
		}
	}

	return nil, "", PlatformSEVSNP, fmt.Errorf("failed to retrieve AMD SEV-SNP report")
}
