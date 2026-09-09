package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDocument_InTotoStatementV1Schema(t *testing.T) {
	var tlsFP, hpkeKey [32]byte
	copy(tlsFP[:], []byte("01234567890123456789012345678901"))
	copy(hpkeKey[:], []byte("abcdefghijklmnopqrstuvwxyzabcdef"))
	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkeKey,
	}

	fakeQuote := []byte("intel-tdx-hardware-quote-bytes")
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

	doc := BuildAttestationDocument(binding, fakeQuote, "dummy-cert-chain", PlatformTDX, certPEM)
	require.NotNil(t, doc)

	// In-toto Statement v1 specification verification
	assert.Equal(t, "https://in-toto.io/Statement/v1", doc.Type)
	assert.Equal(t, StatementTypeV1, doc.Type)
	assert.Equal(t, "https://in-toto.io/attestation/confidential-computing/v0.1", doc.PredicateType)
	assert.Equal(t, PredicateTypeConfidentialComputing, doc.PredicateType)
	assert.Equal(t, PredicateTypeSEVSNP, doc.PredicateType)

	// Placement of certificate: both inside predicate (in-toto canonical) and root (legacy compat)
	assert.Equal(t, certPEM, doc.Predicate.Certificate)
	assert.Equal(t, certPEM, doc.Certificate)

	// JSON serialization validation
	jsonBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	var rawMap map[string]interface{}
	err = json.Unmarshal(jsonBytes, &rawMap)
	require.NoError(t, err)

	assert.Equal(t, StatementTypeV1, rawMap["_type"])
	assert.Equal(t, PredicateTypeConfidentialComputing, rawMap["predicateType"])
	assert.NotNil(t, rawMap["subject"])
	assert.NotNil(t, rawMap["predicate"])
}

func TestDocument_VendorTrustRootsAndSubjects(t *testing.T) {
	var tlsFP, hpkeKey [32]byte
	copy(tlsFP[:], []byte("tls-fingerprint-bytes-32b-length"))
	copy(hpkeKey[:], []byte("hpke-key-bytes-32b-length-string"))
	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkeKey,
	}

	// 1. Intel TDX Platform
	tdxQuote := []byte("genuine-intel-tdx-quote-v4")
	tdxDoc := BuildAttestationDocument(binding, tdxQuote, "intel-pck-chain", PlatformTDX, "tls-cert-pem")
	require.Len(t, tdxDoc.Subject, 2)
	assert.Equal(t, "intel-tdx-quote", tdxDoc.Subject[0].Name)
	expectedTDXDigest := hex.EncodeToString(sha256.New().Sum(tdxQuote))
	tdxHash := sha256.Sum256(tdxQuote)
	assert.Equal(t, hex.EncodeToString(tdxHash[:]), tdxDoc.Subject[0].Digest["sha256"])
	_ = expectedTDXDigest
	assert.Equal(t, "tls-server-certificate", tdxDoc.Subject[1].Name)

	// 2. AMD SEV-SNP Platform
	amdReport := []byte("genuine-amd-sev-snp-report")
	amdDoc := BuildAttestationDocument(binding, amdReport, "amd-vcek-chain", PlatformSEVSNP, "tls-cert-pem")
	require.Len(t, amdDoc.Subject, 2)
	assert.Equal(t, "sev-guest-report", amdDoc.Subject[0].Name)
	amdHash := sha256.Sum256(amdReport)
	assert.Equal(t, hex.EncodeToString(amdHash[:]), amdDoc.Subject[0].Digest["sha256"])
	assert.Equal(t, "tls-server-certificate", amdDoc.Subject[1].Name)

	// 3. NVIDIA CC GPU Evidence Binding
	gpuEv := &GPUEvidence{
		DeviceCount:      1,
		Model:            "NVIDIA H100 80GB HBM3",
		CCEnabled:        true,
		EvidenceReport:   "base64-spdm-measurement-evidence-block",
		CertificateChain: "base64-dice-x509-certificate-chain",
		Nonce:            "deadbeefdeadbeefdeadbeefdeadbeef",
	}

	docWithGPU := BuildAttestationDocumentWithEvidence(binding, tdxQuote, "intel-pck-chain", PlatformTDX, "tls-cert-pem", gpuEv.Nonce, gpuEv)
	require.Len(t, docWithGPU.Subject, 3)
	assert.Equal(t, "intel-tdx-quote", docWithGPU.Subject[0].Name)
	assert.Equal(t, "tls-server-certificate", docWithGPU.Subject[1].Name)
	assert.Equal(t, "nvidia-gpu-evidence", docWithGPU.Subject[2].Name)

	expectedGPUBytes := append([]byte(gpuEv.EvidenceReport), []byte(gpuEv.CertificateChain)...)
	expectedGPUHash := sha256.Sum256(expectedGPUBytes)
	assert.Equal(t, hex.EncodeToString(expectedGPUHash[:]), docWithGPU.Subject[2].Digest["sha256"])
}

func TestDocument_MinItemsSubjectGuarantee(t *testing.T) {
	var tlsFP, hpkeKey [32]byte
	copy(tlsFP[:], []byte("node-tls-fp-32-bytes-long-string"))
	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkeKey,
	}

	// Completely empty hardware quote, cert PEM, and GPU evidence
	doc := BuildAttestationDocumentWithEvidence(binding, nil, "", PlatformNone, "", "", nil)
	require.NotNil(t, doc)

	// in-toto Statement v1 requires subject minItems: 1
	require.GreaterOrEqual(t, len(doc.Subject), 1, "Subject array must have minItems >= 1 per in-toto spec")
	assert.Equal(t, "system-runtime-identity", doc.Subject[0].Name)

	expectedFPHash := sha256.Sum256(tlsFP[:])
	assert.Equal(t, hex.EncodeToString(expectedFPHash[:]), doc.Subject[0].Digest["sha256"])
}

func TestDocument_AutomaticCompositeUserData(t *testing.T) {
	var tlsFP, hpkeKey, nonce [32]byte
	copy(tlsFP[:], []byte("node-tls-fp-32-bytes-long-string"))
	copy(hpkeKey[:], []byte("hpke-public-key-32-bytes-string-"))
	copy(nonce[:], []byte("session-nonce-32-bytes-arbitrary"))

	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkeKey,
	}

	gpuEv := &GPUEvidence{
		DeviceCount:      1,
		Model:            "NVIDIA H100 80GB HBM3",
		CCEnabled:        true,
		EvidenceReport:   "sample-spdm-report",
		CertificateChain: "sample-dice-chain",
	}

	nonceHex := hex.EncodeToString(nonce[:])
	doc := BuildAttestationDocumentWithEvidence(binding, []byte("quote"), "chain", PlatformTDX, "cert", nonceHex, gpuEv)
	require.NotNil(t, doc)

	// Predicate UserData should automatically be the composite user data
	expectedComposite := binding.MarshalComposite(nonce, gpuEv)
	assert.Equal(t, hex.EncodeToString(expectedComposite[:]), doc.Predicate.UserData)

	// Verify constant-time validation succeeds against the doc's UserData
	userDataBytes, err := hex.DecodeString(doc.Predicate.UserData)
	require.NoError(t, err)
	var userDataArr [64]byte
	copy(userDataArr[:], userDataBytes)
	assert.True(t, VerifyCompositeUserData(userDataArr, tlsFP, hpkeKey, nonce, gpuEv))
}

func TestDocument_WriteAttestationToDisk(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "attestation.json")

	doc := &AttestationDocument{
		Type:          StatementTypeV1,
		PredicateType: PredicateTypeConfidentialComputing,
	}
	content := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)

	err := WriteAttestationToDisk(filePath, doc, content)
	require.NoError(t, err)

	readBytes, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, content, readBytes)
}
