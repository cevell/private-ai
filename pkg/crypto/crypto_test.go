package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateNodeKeyPair(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPair)
	require.NotNil(t, keyPair.TLSKey)

	// Verify TLS public key fingerprint
	derPub, err := x509.MarshalPKIXPublicKey(&keyPair.TLSKey.PublicKey)
	require.NoError(t, err)
	expectedFP := sha256.Sum256(derPub)
	assert.Equal(t, expectedFP, keyPair.TLSKeyFP)
	assert.NotEmpty(t, keyPair.HPKEPubKey)
	assert.NotEmpty(t, keyPair.HPKEPrivKey)
}

func TestGenerateSelfSignedCert(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	tlsCert, certPEM, err := GenerateSelfSignedCert(keyPair.TLSKey, "localhost", nil)
	require.NoError(t, err)
	require.NotNil(t, tlsCert)
	assert.NotEmpty(t, certPEM)

	// Verify certificate private key matches
	_, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	assert.True(t, ok)
}

func TestHPKEEncryptionDecryption(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	plaintext := []byte("secret confidential compute payload")
	info := []byte("cevell-cvm-e2e")

	ciphertext, err := EncryptPayloadHPKE(keyPair.HPKEPubKey, plaintext, info)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypted, err := DecryptPayloadHPKE(keyPair.HPKEPrivKey, ciphertext, info)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestZeroize(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	Zeroize(buf)
	for _, b := range buf {
		assert.Equal(t, byte(0), b)
	}
}

func TestKeyPairZeroize(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)
	require.NotNil(t, keyPair)

	keyPair.Zeroize()

	var zero32 [32]byte
	assert.Equal(t, zero32, keyPair.HPKEPrivKey)
	assert.Equal(t, zero32, keyPair.TLSKeyFP)
	assert.Equal(t, int64(0), keyPair.TLSKey.D.Int64())
}

func TestHPKESenderPubExtractionAndRoundtrip(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	plaintext := []byte("confidential inference prompt")
	ciphertext, err := EncryptPayloadHPKE(keyPair.HPKEPubKey, plaintext, nil)
	require.NoError(t, err)

	// Test ExtractSenderPub
	senderPub, err := ExtractSenderPub(ciphertext)
	require.NoError(t, err)
	assert.NotEqual(t, [32]byte{}, senderPub)

	// Test DecryptPayloadHPKEWithSenderPub
	decrypted, extractedPub, err := DecryptPayloadHPKEWithSenderPub(keyPair.HPKEPrivKey, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.Equal(t, senderPub, extractedPub)

	// Test short payload errors
	_, err = ExtractSenderPub([]byte("too short"))
	assert.Error(t, err)

	_, _, err = DecryptPayloadHPKEWithSenderPub(keyPair.HPKEPrivKey, []byte("too short"), nil)
	assert.Error(t, err)
}

func TestBinaryHPKERequestRoundtrip(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	clientPriv, _, err := GenerateHPKEKeyPair()
	require.NoError(t, err)

	plaintext := []byte(`{"model":"qwen","messages":[{"role":"user","content":"hi"}]}`)
	wireBytes, clientSession, err := EncryptBinaryHPKERequest(clientPriv, keyPair.HPKEPubKey, plaintext)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(wireBytes), 60)

	// Server unwrap
	decrypted, serverSession, err := UnwrapBinaryHPKERequest(keyPair.HPKEPrivKey, wireBytes)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.Equal(t, clientSession.ClientPub(), serverSession.ClientPub())
	assert.Equal(t, clientSession.ResponseKey, serverSession.ResponseKey)
	assert.Equal(t, clientSession.ResponseIV, serverSession.ResponseIV)
}

func TestBinaryHPKERequestRejections(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	// 1. Truncated payload < 60 bytes
	_, _, err = UnwrapBinaryHPKERequest(keyPair.HPKEPrivKey, []byte("short-payload"))
	assert.ErrorIs(t, err, ErrPayloadTooShort)

	// 2. Corrupted ciphertext
	clientPriv, _, err := GenerateHPKEKeyPair()
	require.NoError(t, err)
	wireBytes, _, err := EncryptBinaryHPKERequest(clientPriv, keyPair.HPKEPubKey, []byte("test"))
	require.NoError(t, err)
	wireBytes[len(wireBytes)-1] ^= 0xFF // corrupt tag

	_, _, err = UnwrapBinaryHPKERequest(keyPair.HPKEPrivKey, wireBytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting request ciphertext")
}

func TestBinaryHPKEFramedStreaming(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	clientPriv, _, err := GenerateHPKEKeyPair()
	require.NoError(t, err)

	wireBytes, clientSession, err := EncryptBinaryHPKERequest(clientPriv, keyPair.HPKEPubKey, []byte("prompt"))
	require.NoError(t, err)

	_, serverSession, err := UnwrapBinaryHPKERequest(keyPair.HPKEPrivKey, wireBytes)
	require.NoError(t, err)

	// Server streams 3 chunks: 2 token deltas, 1 stream end
	frame1, err := serverSession.EncryptFrame(FrameTypeTokenDelta, []byte("Hello"))
	require.NoError(t, err)
	frame2, err := serverSession.EncryptFrame(FrameTypeTokenDelta, []byte(" world"))
	require.NoError(t, err)
	frame3, err := serverSession.EncryptFrame(FrameTypeStreamEnd, []byte("[DONE]"))
	require.NoError(t, err)

	// Client decrypts frames in order
	fType1, seq1, payload1, err := clientSession.DecryptFrame(frame1)
	require.NoError(t, err)
	assert.Equal(t, FrameTypeTokenDelta, fType1)
	assert.Equal(t, uint32(0), seq1)
	assert.Equal(t, "Hello", string(payload1))

	fType2, seq2, payload2, err := clientSession.DecryptFrame(frame2)
	require.NoError(t, err)
	assert.Equal(t, FrameTypeTokenDelta, fType2)
	assert.Equal(t, uint32(1), seq2)
	assert.Equal(t, " world", string(payload2))

	fType3, seq3, payload3, err := clientSession.DecryptFrame(frame3)
	require.NoError(t, err)
	assert.Equal(t, FrameTypeStreamEnd, fType3)
	assert.Equal(t, uint32(2), seq3)
	assert.Equal(t, "[DONE]", string(payload3))
}

func TestBinaryHPKEFrameTamperResistance(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)
	clientPriv, _, err := GenerateHPKEKeyPair()
	require.NoError(t, err)

	wireBytes, clientSession, err := EncryptBinaryHPKERequest(clientPriv, keyPair.HPKEPubKey, []byte("prompt"))
	require.NoError(t, err)
	_, serverSession, err := UnwrapBinaryHPKERequest(keyPair.HPKEPrivKey, wireBytes)
	require.NoError(t, err)

	frame, err := serverSession.EncryptFrame(FrameTypeTokenDelta, []byte("secret token"))
	require.NoError(t, err)

	// 1. Tamper with FrameType header byte (AAD integrity check)
	tamperedHeader := make([]byte, len(frame))
	copy(tamperedHeader, frame)
	tamperedHeader[0] = FrameTypeCompletion // alter type from Delta to Completion
	_, _, _, err = clientSession.DecryptFrame(tamperedHeader)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting frame payload")

	// 2. Tamper with SeqNum header bytes
	tamperedSeq := make([]byte, len(frame))
	copy(tamperedSeq, frame)
	tamperedSeq[4] ^= 0x01
	_, _, _, err = clientSession.DecryptFrame(tamperedSeq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting frame payload")

	// 3. Tamper with ciphertext byte
	tamperedCipher := make([]byte, len(frame))
	copy(tamperedCipher, frame)
	tamperedCipher[len(tamperedCipher)-1] ^= 0xFF
	_, _, _, err = clientSession.DecryptFrame(tamperedCipher)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting frame payload")

	// 4. Truncate frame
	_, _, _, err = clientSession.DecryptFrame(frame[:20])
	assert.ErrorIs(t, err, ErrFrameTooShort)
}

func TestHPKETamperedCiphertext(t *testing.T) {
	keyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	plaintext := []byte("strictly confidential data")
	ciphertext, err := EncryptPayloadHPKE(keyPair.HPKEPubKey, plaintext, nil)
	require.NoError(t, err)

	// Tamper with one byte in the ciphertext body
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = DecryptPayloadHPKE(keyPair.HPKEPrivKey, tampered, nil)
	assert.Error(t, err, "Decryption must fail when ciphertext or tag is modified")
}

func TestHPKESessionZeroizeAndSeqOverflow(t *testing.T) {
	var key [32]byte
	var iv [12]byte
	copy(key[:], []byte("01234567890123456789012345678901"))
	copy(iv[:], []byte("012345678901"))

	session := &HPKESession{
		RequestKey:  key,
		ResponseKey: key,
		ResponseIV:  iv,
		seqNum:      0xFFFFFFFF,
	}

	// 1. NextSeqNum must return ErrSeqNumOverflow at uint32 limit
	_, err := session.NextSeqNum()
	assert.ErrorIs(t, err, ErrSeqNumOverflow)

	// 2. EncryptFrame must fail closed with ErrSeqNumOverflow
	_, err = session.EncryptFrame(FrameTypeTokenDelta, []byte("payload"))
	assert.ErrorIs(t, err, ErrSeqNumOverflow)

	// 3. Zeroize must wipe key material
	session.Zeroize()
	assert.Equal(t, [32]byte{}, session.RequestKey)
	assert.Equal(t, [32]byte{}, session.ResponseKey)
	assert.Equal(t, [12]byte{}, session.ResponseIV)
	assert.Nil(t, session.respAEAD)
}

func TestHPKELowOrderPublicKeyRejection(t *testing.T) {
	nodeKeyPair, err := GenerateNodeKeyPair()
	require.NoError(t, err)

	// Low-order points that yield all-zero shared secret in Curve25519 (RFC 7748)
	lowOrderPoints := [][32]byte{
		{},  // point 0
		{1}, // point 1
	}

	for _, lowOrder := range lowOrderPoints {
		// 1. EncryptPayloadHPKEWithSenderKey with low-order recipient
		_, err := EncryptPayloadHPKEWithSenderKey(nodeKeyPair.HPKEPrivKey, lowOrder, []byte("test"), nil)
		assert.ErrorIs(t, err, ErrLowOrderPublicKey)

		// 2. DecryptPayloadHPKEWithSenderPub with low-order sender
		dummyPayload := make([]byte, 60)
		copy(dummyPayload[0:32], lowOrder[:])
		_, _, err = DecryptPayloadHPKEWithSenderPub(nodeKeyPair.HPKEPrivKey, dummyPayload, nil)
		assert.ErrorIs(t, err, ErrLowOrderPublicKey)

		// 3. UnwrapBinaryHPKERequest with low-order client
		_, _, err = UnwrapBinaryHPKERequest(nodeKeyPair.HPKEPrivKey, dummyPayload)
		assert.ErrorIs(t, err, ErrLowOrderPublicKey)

		// 4. EncryptBinaryHPKERequest with low-order recipient
		_, _, err = EncryptBinaryHPKERequest(nodeKeyPair.HPKEPrivKey, lowOrder, []byte("test"))
		assert.ErrorIs(t, err, ErrLowOrderPublicKey)
	}
}



