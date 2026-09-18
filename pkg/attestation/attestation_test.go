package attestation

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAMDChainResolution(t *testing.T) {
	milanChain := GetAMDVCEKChain("milan")
	assert.NotEmpty(t, milanChain)
	assert.Contains(t, milanChain, "BEGIN CERTIFICATE")

	genoaChain := GetAMDVCEKChain("genoa")
	assert.NotEmpty(t, genoaChain)
	assert.Contains(t, genoaChain, "BEGIN CERTIFICATE")

	turinChain := GetAMDVCEKChain("turin")
	assert.NotEmpty(t, turinChain)
	assert.Contains(t, turinChain, "BEGIN CERTIFICATE")

	milanVLEK := GetAMDVLEKChain("milan")
	assert.NotEmpty(t, milanVLEK)
	assert.Contains(t, milanVLEK, "BEGIN CERTIFICATE")
}

func TestBindingDataMarshal(t *testing.T) {
	var tlsFP, hpkeKey [32]byte
	for i := 0; i < 32; i++ {
		tlsFP[i] = byte(i)
		hpkeKey[i] = byte(i + 32)
	}

	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkeKey,
	}

	marshaled := binding.Marshal()
	assert.Equal(t, tlsFP[:], marshaled[0:32])
	assert.Equal(t, hpkeKey[:], marshaled[32:64])
}



func TestBuildAttestationDocument(t *testing.T) {
	var tlsFP, hpkeKey [32]byte
	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkeKey,
	}

	fakeQuote := make([]byte, 1184)
	for i := range fakeQuote {
		fakeQuote[i] = 0xAA
	}

	doc := BuildAttestationDocument(binding, fakeQuote, "cert-chain", PlatformSEVSNP, "tls-cert")
	require.NotNil(t, doc)
	assert.Equal(t, PlatformSEVSNP, doc.Predicate.Platform)
	assert.NotEmpty(t, doc.Predicate.RawQuote)
	assert.GreaterOrEqual(t, len(doc.Subject), 1)
	assert.Equal(t, "sev-guest-report", doc.Subject[0].Name)

	h := sha256.Sum256(fakeQuote)
	assert.NotEmpty(t, doc.Subject[0].Digest["sha256"])
	_ = h
}

func TestTDXAttestationDocument(t *testing.T) {
	var tlsFP, hpkeKey [32]byte
	binding := BindingData{
		TLSKeyFingerprint: tlsFP,
		HPKEPublicKey:     hpkeKey,
	}

	fakeTDXQuote := make([]byte, 1024)
	for i := range fakeTDXQuote {
		fakeTDXQuote[i] = 0x55
	}

	doc := BuildAttestationDocument(binding, fakeTDXQuote, "", PlatformTDX, "tls-cert")
	require.NotNil(t, doc)
	assert.Equal(t, PlatformTDX, doc.Predicate.Platform)
	assert.NotEmpty(t, doc.Predicate.RawQuote)
	assert.GreaterOrEqual(t, len(doc.Subject), 1)
	assert.Equal(t, "intel-tdx-quote", doc.Subject[0].Name)
}

func TestCollectGPUEvidence(t *testing.T) {
	var nonce [32]byte
	copy(nonce[:], []byte("0123456789abcdef0123456789abcdef"))

	ev, err := CollectGPUEvidence(nonce)
	require.NoError(t, err)
	require.NotNil(t, ev)
	assert.NotEmpty(t, ev.Nonce)
}
