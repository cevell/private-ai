package attestation

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeCompositeUserData_Structure(t *testing.T) {
	var tlsFP, hpkePub, nonce [32]byte
	for i := 0; i < 32; i++ {
		tlsFP[i] = byte(i + 1)
		hpkePub[i] = byte(i + 33)
		nonce[i] = byte(i + 65)
	}

	gpuEv := &GPUEvidence{
		EvidenceReport:   "mock-evidence-report-hex",
		CertificateChain: "mock-cert-chain-pem",
		DeviceCount:      1,
		CCEnabled:        true,
	}

	userData := ComputeCompositeUserData(tlsFP, hpkePub, nonce, gpuEv)

	// Verify byte range 0..31 is exactly the TLS fingerprint
	assert.Equal(t, tlsFP[:], userData[0:32], "Bytes 0..31 must match TLSKeyFingerprint exactly")

	// Verify byte range 32..63 is SHA256(hpkePub || nonce || gpuDigest)
	gpuCombined := append([]byte(gpuEv.EvidenceReport), []byte(gpuEv.CertificateChain)...)
	expectedGPUDigest := sha256.Sum256(gpuCombined)

	expectedCombined := append(append(append([]byte{}, hpkePub[:]...), nonce[:]...), expectedGPUDigest[:]...)
	expectedCompositeHash := sha256.Sum256(expectedCombined)

	assert.Equal(t, expectedCompositeHash[:], userData[32:64], "Bytes 32..63 must match composite SHA-256 hash")
}

func TestComputeCompositeUserData_NilAndEmptyGPU(t *testing.T) {
	var tlsFP, hpkePub, nonce [32]byte
	copy(tlsFP[:], "mock-tls-fp")
	copy(hpkePub[:], "mock-hpke-pub")
	copy(nonce[:], "mock-nonce")

	// 1. When gpuEv == nil (CPU-only CVM)
	userDataNil := ComputeCompositeUserData(tlsFP, hpkePub, nonce, nil)
	assert.Equal(t, tlsFP[:], userDataNil[0:32])

	var zeroGPUDigest [32]byte
	combinedExpected := append(append(append([]byte{}, hpkePub[:]...), nonce[:]...), zeroGPUDigest[:]...)
	expectedHash := sha256.Sum256(combinedExpected)
	assert.Equal(t, expectedHash[:], userDataNil[32:64])

	// 2. When gpuEv is empty (len(EvidenceReport) == 0)
	userDataEmpty := ComputeCompositeUserData(tlsFP, hpkePub, nonce, &GPUEvidence{})
	assert.Equal(t, userDataNil, userDataEmpty, "Empty GPUEvidence should produce identical digest to nil GPUEvidence")
}

func TestVerifyCompositeUserData_ValidationAndTamperResistance(t *testing.T) {
	var tlsFP, hpkePub, nonce [32]byte
	copy(tlsFP[:], "node-tls-public-key-fingerprint-")
	copy(hpkePub[:], "node-hpke-x25519-public-key-here-")
	copy(nonce[:], "client-session-nonce-bytes-here-")

	gpuEv := &GPUEvidence{
		EvidenceReport:   "genuine-h100-spdm-measurement-block",
		CertificateChain: "genuine-nvidia-dice-cert-chain",
		DeviceCount:      1,
		CCEnabled:        true,
	}

	validUserData := ComputeCompositeUserData(tlsFP, hpkePub, nonce, gpuEv)

	// Valid verification
	require.True(t, VerifyCompositeUserData(validUserData, tlsFP, hpkePub, nonce, gpuEv), "Valid user data must verify successfully")

	// Tampered TLS fingerprint
	var tamperedTLS [32]byte
	copy(tamperedTLS[:], tlsFP[:])
	tamperedTLS[0] ^= 0xFF
	assert.False(t, VerifyCompositeUserData(validUserData, tamperedTLS, hpkePub, nonce, gpuEv), "Tampered TLS fingerprint must be rejected")

	// Tampered HPKE public key
	var tamperedHPKE [32]byte
	copy(tamperedHPKE[:], hpkePub[:])
	tamperedHPKE[0] ^= 0xFF
	assert.False(t, VerifyCompositeUserData(validUserData, tlsFP, tamperedHPKE, nonce, gpuEv), "Tampered HPKE key must be rejected")

	// Tampered nonce
	var tamperedNonce [32]byte
	copy(tamperedNonce[:], nonce[:])
	tamperedNonce[0] ^= 0xFF
	assert.False(t, VerifyCompositeUserData(validUserData, tlsFP, hpkePub, tamperedNonce, gpuEv), "Tampered nonce must be rejected")

	// Tampered GPU Evidence Report (splicing attempt)
	tamperedGPUEv := &GPUEvidence{
		EvidenceReport:   "spliced-foreign-gpu-report",
		CertificateChain: gpuEv.CertificateChain,
	}
	assert.False(t, VerifyCompositeUserData(validUserData, tlsFP, hpkePub, nonce, tamperedGPUEv), "Spliced GPU report must be rejected")

	// Tampered GPU Certificate Chain
	tamperedGPUCerts := &GPUEvidence{
		EvidenceReport:   gpuEv.EvidenceReport,
		CertificateChain: "forged-cert-chain",
	}
	assert.False(t, VerifyCompositeUserData(validUserData, tlsFP, hpkePub, nonce, tamperedGPUCerts), "Forged GPU certificate chain must be rejected")
}

func TestBindingData_MarshalComposite(t *testing.T) {
	var tlsFP, hpkePub, nonce [32]byte
	copy(tlsFP[:], "test-tls-fp")
	copy(hpkePub[:], "test-hpke-pub")
	copy(nonce[:], "test-nonce")

	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkePub,
	}

	gpuEv := &GPUEvidence{
		EvidenceReport:   "report-123",
		CertificateChain: "cert-456",
	}

	composite := binding.MarshalComposite(nonce, gpuEv)
	direct := ComputeCompositeUserData(tlsFP, hpkePub, nonce, gpuEv)

	assert.Equal(t, direct, composite, "MarshalComposite must produce identical bytes to ComputeCompositeUserData")
}
