package attestation

import (
	"crypto/sha256"
	"crypto/subtle"
)

const SealedUserDataDomain = "cevell-sealed-v1"

// ComputeCompositeUserData calculates the canonical 64-byte REPORT_DATA / USER_DATA payload
// for Intel TDX and AMD SEV-SNP hardware quotes in the unsealed state.
//
// Cryptographic Layout:
// - Bytes 0..31:  SHA-256 fingerprint of the node TLS server public key (SPKI).
// - Bytes 32..63: Composite SHA-256 digest of (HPKEPublicKey || Nonce || GPU_Evidence_Digest || AuthPublicKey).
//
// If no GPU is present or cc_enabled is false, GPU_Evidence_Digest defaults to an all-zero [32]byte,
// guaranteeing clean, deterministic cryptographic behavior across both CPU-only and GPU CVM instances.
func ComputeCompositeUserData(tlsFP [32]byte, hpkePub [32]byte, nonce [32]byte, gpuEv *GPUEvidence, authPub [32]byte) [64]byte {
	return ComputeCompositeUserDataWithSeal(tlsFP, hpkePub, nonce, gpuEv, authPub, false)
}

// ComputeCompositeUserDataWithSeal calculates the canonical 64-byte REPORT_DATA / USER_DATA payload
// and optionally commits to the hermetic sealed state ("cevell-sealed-v1") in bytes 32..63.
func ComputeCompositeUserDataWithSeal(tlsFP [32]byte, hpkePub [32]byte, nonce [32]byte, gpuEv *GPUEvidence, authPub [32]byte, sealed bool) [64]byte {
	var userData [64]byte
	copy(userData[0:32], tlsFP[:])

	var gpuDigest [32]byte
	if gpuEv != nil && len(gpuEv.EvidenceReport) > 0 {
		gpuCombined := append([]byte(gpuEv.EvidenceReport), []byte(gpuEv.CertificateChain)...)
		gpuDigest = sha256.Sum256(gpuCombined)
	}

	combined := append(append(append(append([]byte{}, hpkePub[:]...), nonce[:]...), gpuDigest[:]...), authPub[:]...)
	if sealed {
		combined = append(combined, []byte(SealedUserDataDomain)...)
	}
	combinedHash := sha256.Sum256(combined)
	copy(userData[32:64], combinedHash[:])

	return userData
}

// VerifyCompositeUserData cryptographically verifies whether the 64-byte hardware quote
// REPORT_DATA accurately commits to the claimed TLS fingerprint, HPKE public key, session nonce,
// NVIDIA GPU evidence, and tenant authorized public key (unsealed state).
func VerifyCompositeUserData(userData [64]byte, tlsFP [32]byte, hpkePub [32]byte, nonce [32]byte, gpuEv *GPUEvidence, authPub [32]byte) bool {
	return VerifyCompositeUserDataWithSeal(userData, tlsFP, hpkePub, nonce, gpuEv, authPub, false)
}

// VerifyCompositeUserDataWithSeal verifies the 64-byte hardware quote REPORT_DATA
// against the expected identity anchors and enclave seal state.
func VerifyCompositeUserDataWithSeal(userData [64]byte, tlsFP [32]byte, hpkePub [32]byte, nonce [32]byte, gpuEv *GPUEvidence, authPub [32]byte, sealed bool) bool {
	expected := ComputeCompositeUserDataWithSeal(tlsFP, hpkePub, nonce, gpuEv, authPub, sealed)
	return subtle.ConstantTimeCompare(userData[:], expected[:]) == 1
}

// BindingData contains the cryptographic identity materials bound into the 64-byte REPORT_DATA.
type BindingData struct {
	TLSKeyFingerprint [32]byte
	HPKEPublicKey     [32]byte
	AuthPublicKey     [32]byte
	Sealed            bool
}

// Marshal encodes the legacy 64-byte user data payload (TLSKeyFingerprint || HPKEPublicKey).
func (b *BindingData) Marshal() [64]byte {
	var out [64]byte
	copy(out[0:32], b.TLSKeyFingerprint[:])
	copy(out[32:64], b.HPKEPublicKey[:])
	return out
}

// MarshalComposite encodes the 64-byte payload including session nonce, GPU evidence, tenant public key, and seal state.
func (b *BindingData) MarshalComposite(nonce [32]byte, gpuEv *GPUEvidence) [64]byte {
	return ComputeCompositeUserDataWithSeal(b.TLSKeyFingerprint, b.HPKEPublicKey, nonce, gpuEv, b.AuthPublicKey, b.Sealed)
}
