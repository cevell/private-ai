package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
)

const (
	// StatementTypeV1 is the official in-toto Statement v1 specification URI.
	StatementTypeV1 = "https://in-toto.io/Statement/v1"

	// PredicateTypeConfidentialComputing is the vendor-neutral in-toto predicate type for CC evidence.
	PredicateTypeConfidentialComputing = "https://in-toto.io/attestation/confidential-computing/v0.1"

	// PredicateTypeSEVSNP is retained as an alias to PredicateTypeConfidentialComputing for backward compatibility.
	PredicateTypeSEVSNP = PredicateTypeConfidentialComputing
)

// InTotoSubject represents an individual measured entity bound by the statement.
type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ConfidentialComputingPredicate holds the hardware and cryptographic evidence claims.
type ConfidentialComputingPredicate struct {
	Platform         string       `json:"platform"`
	RawQuote         string       `json:"raw_quote"`
	CertificateChain string       `json:"certificate_chain,omitempty"`
	Certificate      string       `json:"certificate,omitempty"`
	TLSFingerprint   string       `json:"tls_fingerprint"`
	HPKEPublicKey    string       `json:"hpke_public_key"`
	UserData         string       `json:"user_data,omitempty"`
	Nonce            string       `json:"nonce,omitempty"`
	GPUEvidence      *GPUEvidence `json:"gpu_evidence,omitempty"`
}

// AttestationDocument represents the standard in-toto Statement v1 envelope.
type AttestationDocument struct {
	Type          string                         `json:"_type"`
	PredicateType string                         `json:"predicateType"`
	Subject       []InTotoSubject                `json:"subject"`
	Predicate     ConfidentialComputingPredicate `json:"predicate"`
	Certificate   string                         `json:"certificate,omitempty"`
}

// BuildAttestationDocument constructs the structured JSON attestation envelope.
func BuildAttestationDocument(binding BindingData, rawQuote []byte, certChain, platform, tlsCertPEM string) *AttestationDocument {
	return BuildAttestationDocumentWithEvidence(binding, rawQuote, certChain, platform, tlsCertPEM, "", nil)
}

// BuildAttestationDocumentWithEvidence constructs the in-toto Statement v1 envelope with composite evidence.
func BuildAttestationDocumentWithEvidence(binding BindingData, rawQuote []byte, certChain, platform, tlsCertPEM string, nonce string, gpuEv *GPUEvidence) *AttestationDocument {
	doc := &AttestationDocument{
		Type:          StatementTypeV1,
		PredicateType: PredicateTypeConfidentialComputing,
		Certificate:   tlsCertPEM, // Retained at root for legacy verifiers
	}

	doc.Predicate.Platform = platform
	doc.Predicate.TLSFingerprint = hex.EncodeToString(binding.TLSKeyFingerprint[:])
	doc.Predicate.HPKEPublicKey = hex.EncodeToString(binding.HPKEPublicKey[:])
	doc.Predicate.Certificate = tlsCertPEM // Standard in-toto location inside predicate
	doc.Predicate.CertificateChain = certChain
	doc.Predicate.Nonce = nonce
	doc.Predicate.GPUEvidence = gpuEv

	// Parse nonce into 32-byte array if provided
	var nonceBytes [32]byte
	if nonce != "" {
		if raw, err := hex.DecodeString(nonce); err == nil && len(raw) == 32 {
			copy(nonceBytes[:], raw)
		} else {
			nonceBytes = sha256.Sum256([]byte(nonce))
		}
	}

	// Compute composite user data if nonce or GPU evidence is present
	if nonce != "" || (gpuEv != nil && (gpuEv.DeviceCount > 0 || len(gpuEv.EvidenceReport) > 0)) {
		composite := ComputeCompositeUserData(binding.TLSKeyFingerprint, binding.HPKEPublicKey, nonceBytes, gpuEv)
		doc.Predicate.UserData = hex.EncodeToString(composite[:])
	} else {
		defaultUserData := binding.Marshal()
		doc.Predicate.UserData = hex.EncodeToString(defaultUserData[:])
	}

	subjects := make([]InTotoSubject, 0)

	if len(rawQuote) > 0 {
		doc.Predicate.RawQuote = base64.StdEncoding.EncodeToString(rawQuote)
		h := sha256.Sum256(rawQuote)
		reportName := "hardware-enclave-quote"
		if platform == PlatformTDX {
			reportName = "intel-tdx-quote"
		} else if platform == PlatformSEVSNP {
			reportName = "sev-guest-report"
		}
		subjects = append(subjects, InTotoSubject{
			Name: reportName,
			Digest: map[string]string{
				"sha256": hex.EncodeToString(h[:]),
			},
		})
	}

	// Bind TLS server certificate as measured subject if present
	if tlsCertPEM != "" {
		certHash := sha256.Sum256([]byte(tlsCertPEM))
		subjects = append(subjects, InTotoSubject{
			Name: "tls-server-certificate",
			Digest: map[string]string{
				"sha256": hex.EncodeToString(certHash[:]),
			},
		})
	}

	// Bind GPU accelerator evidence as measured subject if present
	if gpuEv != nil && (gpuEv.DeviceCount > 0 || len(gpuEv.EvidenceReport) > 0) {
		evidenceBytes := append([]byte(gpuEv.EvidenceReport), []byte(gpuEv.CertificateChain)...)
		evidenceHash := sha256.Sum256(evidenceBytes)
		subjects = append(subjects, InTotoSubject{
			Name: "nvidia-gpu-evidence",
			Digest: map[string]string{
				"sha256": hex.EncodeToString(evidenceHash[:]),
			},
		})
	}

	// In-toto Statement v1 requires minItems: 1 for subjects.
	// In degraded / fallback mode where hardware report and TLS cert are absent,
	// record the node runtime identity fingerprint.
	if len(subjects) == 0 {
		fpHash := sha256.Sum256(binding.TLSKeyFingerprint[:])
		subjects = append(subjects, InTotoSubject{
			Name: "system-runtime-identity",
			Digest: map[string]string{
				"sha256": hex.EncodeToString(fpHash[:]),
			},
		})
	}

	doc.Subject = subjects
	return doc
}

// WriteAttestationToDisk writes the attestation document to disk for runtime inspection.
func WriteAttestationToDisk(path string, doc *AttestationDocument, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
