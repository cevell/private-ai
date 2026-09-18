package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	wirev1 "github.com/cevell/private-ai/pkg/proto/v1"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrInvalidProtoEnvelope indicates that the payload cannot be parsed as a valid EncryptedInferenceRequest.
	ErrInvalidProtoEnvelope = errors.New("invalid protobuf encrypted request envelope")
	// ErrUnsupportedVersion indicates the envelope version is not supported.
	ErrUnsupportedVersion = errors.New("unsupported protobuf wire version")
	// ErrUnsupportedCipherSuite indicates an unknown or unapproved ciphersuite.
	ErrUnsupportedCipherSuite = errors.New("unsupported ciphersuite: must be DHKEM_X25519_AES256_GCM")
	// ErrInvalidClientKeyLen indicates the client ephemeral key is not 32 bytes.
	ErrInvalidClientKeyLen = errors.New("client ephemeral public key must be exactly 32 bytes")
	// ErrInvalidNonceLen indicates the AEAD nonce is not 12 bytes.
	ErrInvalidNonceLen = errors.New("request nonce must be exactly 12 bytes")
	// ErrAttestationMismatch indicates the client's bound attestation hash does not match this enclave.
	ErrAttestationMismatch = errors.New("attestation binding hash does not match target enclave")
	// ErrFrameTagMismatch indicates the frame authentication tag does not match or payload was altered.
	ErrFrameTagMismatch = errors.New("frame authentication tag mismatch or payload corrupted")
)

// UnwrapProtoHPKERequest deserializes and decrypts an EncryptedInferenceRequest protobuf message.
// It verifies the client ephemeral key, nonce, optional attestation binding hash, derives the
// symmetric keys via HKDF-SHA256, and returns the decrypted inner payload, initialized session,
// and original protobuf request metadata.
func UnwrapProtoHPKERequest(recipientPriv [32]byte, rawBody []byte, expectedBindingHash []byte) ([]byte, *HPKESession, *wirev1.EncryptedInferenceRequest, error) {
	if len(rawBody) < 40 {
		return nil, nil, nil, ErrInvalidProtoEnvelope
	}

	var req wirev1.EncryptedInferenceRequest
	if err := proto.Unmarshal(rawBody, &req); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidProtoEnvelope, err)
	}

	if req.Version != 1 {
		return nil, nil, nil, fmt.Errorf("%w: got version %d, expected 1", ErrUnsupportedVersion, req.Version)
	}

	if req.CipherSuite != wirev1.CipherSuite_CIPHER_SUITE_DHKEM_X25519_AES256_GCM {
		return nil, nil, nil, ErrUnsupportedCipherSuite
	}

	if len(req.ClientEphemeralPublicKey) != 32 {
		return nil, nil, nil, ErrInvalidClientKeyLen
	}

	if len(req.Nonce) != 12 {
		return nil, nil, nil, ErrInvalidNonceLen
	}

	if len(req.EncryptedPayload) < GCMTagLen {
		return nil, nil, nil, errors.New("encrypted payload too short for AEAD tag")
	}

	// Verify attestation binding hash if both client provided it and enclave has it
	if len(expectedBindingHash) > 0 && len(req.AttestationBindingHash) > 0 {
		if subtle.ConstantTimeCompare(req.AttestationBindingHash, expectedBindingHash) != 1 {
			return nil, nil, nil, ErrAttestationMismatch
		}
	}

	var clientEphPub [32]byte
	copy(clientEphPub[:], req.ClientEphemeralPublicKey)

	// 1. Compute shared secret
	sharedSecret, err := computeX25519SharedSecret(recipientPriv[:], clientEphPub[:])
	if err != nil {
		return nil, nil, nil, err
	}
	defer Zeroize(sharedSecret)

	// 2. Derive request key, response key, and response IV via HKDF-SHA256
	reqKeyReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("cevell-hpke-req-aes-gcm"))
	var reqKey [32]byte
	if _, err := io.ReadFull(reqKeyReader, reqKey[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("deriving request key: %w", err)
	}
	defer Zeroize(reqKey[:])

	respKeyReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("cevell-hpke-resp-aes-gcm"))
	var respKey [32]byte
	if _, err := io.ReadFull(respKeyReader, respKey[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("deriving response key: %w", err)
	}
	defer Zeroize(respKey[:])

	respIVReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("cevell-hpke-resp-base-iv"))
	var respIV [12]byte
	if _, err := io.ReadFull(respIVReader, respIV[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("deriving response base IV: %w", err)
	}
	defer Zeroize(respIV[:])

	// 3. Decrypt request body with AES-256-GCM
	block, err := aes.NewCipher(reqKey[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, req.Nonce, req.EncryptedPayload, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypting request ciphertext: %w", err)
	}

	session := &HPKESession{
		ClientEphPub: clientEphPub,
		RequestKey:   reqKey,
		ResponseKey:  respKey,
		ResponseIV:   respIV,
		seqNum:       0,
	}
	if _, err := session.getOrInitRespAEAD(); err != nil {
		return nil, nil, nil, fmt.Errorf("initializing response cipher: %w", err)
	}

	return plaintext, session, &req, nil
}

// EncryptProtoHPKERequest encrypts a request payload into a protobuf EncryptedInferenceRequest.
// Returns the serialized protobuf bytes and the client-side session for decrypting response frames.
func EncryptProtoHPKERequest(clientPriv [32]byte, recipientPub [32]byte, plaintext []byte, attestationBindingHash []byte, requestID string) ([]byte, *HPKESession, error) {
	var clientPub [32]byte
	curve25519.ScalarBaseMult(&clientPub, &clientPriv)

	sharedSecret, err := computeX25519SharedSecret(clientPriv[:], recipientPub[:])
	if err != nil {
		return nil, nil, err
	}
	defer Zeroize(sharedSecret)

	reqKeyReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("cevell-hpke-req-aes-gcm"))
	var reqKey [32]byte
	if _, err := io.ReadFull(reqKeyReader, reqKey[:]); err != nil {
		return nil, nil, fmt.Errorf("deriving request key: %w", err)
	}
	defer Zeroize(reqKey[:])

	respKeyReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("cevell-hpke-resp-aes-gcm"))
	var respKey [32]byte
	if _, err := io.ReadFull(respKeyReader, respKey[:]); err != nil {
		return nil, nil, fmt.Errorf("deriving response key: %w", err)
	}
	defer Zeroize(respKey[:])

	respIVReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("cevell-hpke-resp-base-iv"))
	var respIV [12]byte
	if _, err := io.ReadFull(respIVReader, respIV[:]); err != nil {
		return nil, nil, fmt.Errorf("deriving response base IV: %w", err)
	}
	defer Zeroize(respIV[:])

	block, err := aes.NewCipher(reqKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating request nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	req := &wirev1.EncryptedInferenceRequest{
		Version:                  1,
		CipherSuite:              wirev1.CipherSuite_CIPHER_SUITE_DHKEM_X25519_AES256_GCM,
		ClientEphemeralPublicKey: clientPub[:],
		Nonce:                    nonce,
		EncryptedPayload:         ciphertext,
		AttestationBindingHash:   attestationBindingHash,
		RequestId:                requestID,
		Compression:              wirev1.CompressionCodec_COMPRESSION_NONE,
	}

	protoBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling EncryptedInferenceRequest: %w", err)
	}

	session := &HPKESession{
		ClientEphPub: clientPub,
		RequestKey:   reqKey,
		ResponseKey:  respKey,
		ResponseIV:   respIV,
		seqNum:       0,
	}
	if _, err := session.getOrInitRespAEAD(); err != nil {
		return nil, nil, fmt.Errorf("initializing response cipher: %w", err)
	}

	return protoBytes, session, nil
}

// computeFrameAAD constructs Additional Authenticated Data (AAD) for a StreamingInferenceFrame.
// AAD = [SeqNum (4B BE)][FrameType (1B)][TimestampNs (8B BE)] = 13 bytes.
func computeFrameAAD(seq uint32, frameType wirev1.FrameType, timestampNs int64) []byte {
	aad := make([]byte, 13)
	binary.BigEndian.PutUint32(aad[0:4], seq)
	aad[4] = byte(frameType)
	binary.BigEndian.PutUint64(aad[5:13], uint64(timestampNs))
	return aad
}

// EncryptProtoFrame serializes plaintext into an authenticated StreamingInferenceFrame protobuf message,
// prefixed with a 4-byte big-endian length delimiter.
// Wire format: [4B BE Length][Serialized StreamingInferenceFrame Protobuf]
func (s *HPKESession) EncryptProtoFrame(frameType wirev1.FrameType, plaintext []byte) ([]byte, error) {
	gcm, err := s.getOrInitRespAEAD()
	if err != nil {
		return nil, err
	}

	seq, err := s.NextSeqNum()
	if err != nil {
		return nil, err
	}

	nowNs := time.Now().UnixNano()
	aad := computeFrameAAD(seq, frameType, nowNs)
	nonce := computeFrameNonce(s.ResponseIV, seq)

	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	if len(sealed) < GCMTagLen {
		return nil, errors.New("sealed frame payload unexpectedly short")
	}

	ciphertext := sealed[:len(sealed)-GCMTagLen]
	tag := sealed[len(sealed)-GCMTagLen:]

	frame := &wirev1.StreamingInferenceFrame{
		SequenceNumber:   seq,
		FrameType:        frameType,
		EncryptedPayload: ciphertext,
		AuthTag:          tag,
		TimestampNs:      nowNs,
	}

	protoBytes, err := proto.Marshal(frame)
	if err != nil {
		return nil, fmt.Errorf("marshaling StreamingInferenceFrame: %w", err)
	}

	out := make([]byte, 4+len(protoBytes))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(protoBytes)))
	copy(out[4:], protoBytes)
	return out, nil
}

// DecryptProtoFrame parses and decrypts a length-delimited StreamingInferenceFrame protobuf message.
// Validates AAD, AEAD authentication tag, and sequence number.
func (s *HPKESession) DecryptProtoFrame(frameBytes []byte) (wirev1.FrameType, uint32, []byte, error) {
	if len(frameBytes) < 4 {
		return 0, 0, nil, errors.New("frame too short for length delimiter")
	}

	protoLen := binary.BigEndian.Uint32(frameBytes[0:4])
	if uint32(len(frameBytes)-4) != protoLen {
		return 0, 0, nil, fmt.Errorf("frame length mismatch: header specifies %d bytes, got %d", protoLen, len(frameBytes)-4)
	}

	var frame wirev1.StreamingInferenceFrame
	if err := proto.Unmarshal(frameBytes[4:], &frame); err != nil {
		return 0, 0, nil, fmt.Errorf("unmarshaling StreamingInferenceFrame: %w", err)
	}

	gcm, err := s.getOrInitRespAEAD()
	if err != nil {
		return 0, 0, nil, err
	}

	nonce := computeFrameNonce(s.ResponseIV, frame.SequenceNumber)
	aad := computeFrameAAD(frame.SequenceNumber, frame.FrameType, frame.TimestampNs)

	ciphertextWithTag := make([]byte, len(frame.EncryptedPayload)+len(frame.AuthTag))
	copy(ciphertextWithTag, frame.EncryptedPayload)
	copy(ciphertextWithTag[len(frame.EncryptedPayload):], frame.AuthTag)

	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, aad)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("%w: %v", ErrFrameTagMismatch, err)
	}

	return frame.FrameType, frame.SequenceNumber, plaintext, nil
}
