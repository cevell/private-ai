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
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DefaultHPKEInfo is the default context salt for Cevell end-to-end encryption.
var DefaultHPKEInfo = []byte("cevell-cvm-e2e")

// ErrLowOrderPublicKey is returned when an X25519 public key is a low-order point yielding an all-zero shared secret.
var ErrLowOrderPublicKey = errors.New("RFC 7748 / RFC 9180: low-order Curve25519 public key produces all-zero shared secret")

// Zeroize securely overwrites sensitive byte slices with zeros, preventing compiler dead-code elimination.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// computeX25519SharedSecret computes X25519 key agreement and enforces RFC 7748 / RFC 9180 validation
// by rejecting low-order public keys that produce an all-zero shared secret.
func computeX25519SharedSecret(priv, pub []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(priv, pub)
	if err != nil {
		if strings.Contains(err.Error(), "low order point") {
			return nil, fmt.Errorf("%w: %v", ErrLowOrderPublicKey, err)
		}
		return nil, fmt.Errorf("X25519 key agreement failed: %w", err)
	}
	var allZero [32]byte
	if subtle.ConstantTimeCompare(sharedSecret, allZero[:]) == 1 {
		Zeroize(sharedSecret)
		return nil, ErrLowOrderPublicKey
	}
	return sharedSecret, nil
}

// EncryptPayloadHPKEWithSenderKey encrypts plaintext using an explicit sender X25519 private key.
func EncryptPayloadHPKEWithSenderKey(senderPriv [32]byte, recipientPub [32]byte, plaintext, info []byte) ([]byte, error) {
	if len(info) == 0 {
		info = DefaultHPKEInfo
	}

	var senderPub [32]byte
	curve25519.ScalarBaseMult(&senderPub, &senderPriv)

	// 1. Compute shared secret
	sharedSecret, err := computeX25519SharedSecret(senderPriv[:], recipientPub[:])
	if err != nil {
		return nil, err
	}
	defer Zeroize(sharedSecret)

	// 2. Derive 32-byte AES key via HKDF
	kdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("deriving encryption key: %w", err)
	}
	defer Zeroize(aesKey)

	// 3. Encrypt with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Envelope: [senderPub (32)] || [nonce (12)] || [ciphertext]
	out := make([]byte, 32+len(nonce)+len(ciphertext))
	copy(out[0:32], senderPub[:])
	copy(out[32:32+len(nonce)], nonce)
	copy(out[32+len(nonce):], ciphertext)

	return out, nil
}

// EncryptPayloadHPKE encrypts plaintext using DHKEM(X25519, HKDF-SHA256) and AES-GCM with a fresh ephemeral key.
func EncryptPayloadHPKE(recipientPub [32]byte, plaintext, info []byte) ([]byte, error) {
	var ephPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return nil, fmt.Errorf("generating ephemeral private key: %w", err)
	}
	defer Zeroize(ephPriv[:])
	return EncryptPayloadHPKEWithSenderKey(ephPriv, recipientPub, plaintext, info)
}

// ExtractSenderPub extracts the 32-byte sender ephemeral public key from an HPKE envelope.
func ExtractSenderPub(payload []byte) ([32]byte, error) {
	var ephPub [32]byte
	if len(payload) < 32+12+16 {
		return ephPub, fmt.Errorf("payload too short for HPKE envelope: got %d bytes, need at least 60", len(payload))
	}
	copy(ephPub[:], payload[0:32])
	return ephPub, nil
}

// DecryptPayloadHPKEWithSenderPub decrypts an HPKE payload and extracts the sender's ephemeral public key.
func DecryptPayloadHPKEWithSenderPub(recipientPriv [32]byte, payload, info []byte) ([]byte, [32]byte, error) {
	var ephPub [32]byte
	if len(payload) < 32+12+16 {
		return nil, ephPub, fmt.Errorf("payload too short for decryption: got %d bytes, need at least 60", len(payload))
	}

	copy(ephPub[:], payload[0:32])
	nonce := payload[32 : 32+12]
	ciphertext := payload[32+12:]

	if len(info) == 0 {
		info = DefaultHPKEInfo
	}

	sharedSecret, err := computeX25519SharedSecret(recipientPriv[:], ephPub[:])
	if err != nil {
		return nil, ephPub, err
	}
	defer Zeroize(sharedSecret)

	kdfReader := hkdf.New(sha256.New, sharedSecret, nil, info)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(kdfReader, aesKey); err != nil {
		return nil, ephPub, fmt.Errorf("deriving decryption key: %w", err)
	}
	defer Zeroize(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, ephPub, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ephPub, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ephPub, fmt.Errorf("decrypting ciphertext: %w", err)
	}

	return plaintext, ephPub, nil
}

// DecryptPayloadHPKE decrypts an encrypted payload using the recipient's X25519 private key.
func DecryptPayloadHPKE(recipientPriv [32]byte, payload, info []byte) ([]byte, error) {
	plaintext, _, err := DecryptPayloadHPKEWithSenderPub(recipientPriv, payload, info)
	return plaintext, err
}

// Frame types for binary wire protocol.
const (
	FrameTypeTokenDelta byte = 0x01 // Streaming token chunk (UTF-8 delta)
	FrameTypeCompletion byte = 0x02 // Non-streaming or final completion payload
	FrameTypeStreamEnd  byte = 0x03 // End of stream signal ([DONE])
	FrameTypeError      byte = 0xFF // Enclave error frame
)

const (
	// BinaryFrameHeaderLen is the fixed size of a binary wire frame header:
	// 1 byte FrameType + 4 bytes SeqNum + 4 bytes PayloadLen = 9 bytes.
	BinaryFrameHeaderLen = 9
	// GCMTagLen is the standard AES-GCM authentication tag size.
	GCMTagLen = 16
	// MinBinaryRequestLen is: ClientEphPub(32) + ReqNonce(12) + GCMTag(16) = 60 bytes.
	MinBinaryRequestLen = 32 + 12 + 16
)

var (
	ErrPayloadTooShort     = errors.New("payload too short for binary HPKE request envelope (minimum 60 bytes required)")
	ErrFrameTooShort       = errors.New("binary frame too short (minimum 25 bytes required)")
	ErrFrameLengthMismatch = errors.New("binary frame length does not match payload length header")
	ErrSeqNumOverflow      = errors.New("sequence counter overflow: session must terminate to prevent nonce reuse")
)

// HPKESession manages symmetric AEAD encryption for bidirectional streaming sessions.
type HPKESession struct {
	ClientEphPub [32]byte
	RequestKey   [32]byte
	ResponseKey  [32]byte
	ResponseIV   [12]byte
	mu           sync.Mutex
	seqNum       uint32
	respAEAD     cipher.AEAD
}

// Zeroize securely wipes session symmetric keys from memory.
func (s *HPKESession) Zeroize() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	Zeroize(s.RequestKey[:])
	Zeroize(s.ResponseKey[:])
	Zeroize(s.ResponseIV[:])
	Zeroize(s.ClientEphPub[:])
	s.respAEAD = nil
}

// getOrInitRespAEAD returns the cached response AEAD cipher or initializes it.
func (s *HPKESession) getOrInitRespAEAD() (cipher.AEAD, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.respAEAD != nil {
		return s.respAEAD, nil
	}
	block, err := aes.NewCipher(s.ResponseKey[:])
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	s.respAEAD = gcm
	return s.respAEAD, nil
}

// ClientPub returns the client's ephemeral public key.
func (s *HPKESession) ClientPub() [32]byte {
	return s.ClientEphPub
}

// NextSeqNum atomically increments and returns the sequence number.
// Returns ErrSeqNumOverflow if the counter reaches uint32 capacity, preventing nonce reuse.
func (s *HPKESession) NextSeqNum() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seqNum == 0xFFFFFFFF {
		return 0, ErrSeqNumOverflow
	}
	seq := s.seqNum
	s.seqNum++
	return seq, nil
}

// computeFrameNonce derives a unique 12-byte AEAD nonce by XORing the sequence number into the base IV.
func computeFrameNonce(baseIV [12]byte, seq uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, baseIV[:])
	var seqBytes [4]byte
	binary.BigEndian.PutUint32(seqBytes[:], seq)
	nonce[8] ^= seqBytes[0]
	nonce[9] ^= seqBytes[1]
	nonce[10] ^= seqBytes[2]
	nonce[11] ^= seqBytes[3]
	return nonce
}

// EncryptFrame creates a framed binary AEAD message authenticated with AAD.
// Wire format: [Type (1B)][SeqNum (4B)][PayloadLen (4B)][Ciphertext (Len B)][Tag (16B)]
func (s *HPKESession) EncryptFrame(frameType byte, plaintext []byte) ([]byte, error) {
	gcm, err := s.getOrInitRespAEAD()
	if err != nil {
		return nil, err
	}

	seq, err := s.NextSeqNum()
	if err != nil {
		return nil, err
	}
	header := make([]byte, BinaryFrameHeaderLen)
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:5], seq)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(plaintext)))

	nonce := computeFrameNonce(s.ResponseIV, seq)
	// Authenticate the 9-byte header as additionalData (AAD)
	sealed := gcm.Seal(nil, nonce, plaintext, header)

	out := make([]byte, BinaryFrameHeaderLen+len(sealed))
	copy(out[0:BinaryFrameHeaderLen], header)
	copy(out[BinaryFrameHeaderLen:], sealed)
	return out, nil
}

// DecryptFrame parses and decrypts a binary wire frame, validating its AEAD tag and header AAD.
func (s *HPKESession) DecryptFrame(frameBytes []byte) (byte, uint32, []byte, error) {
	if len(frameBytes) < BinaryFrameHeaderLen+GCMTagLen {
		return 0, 0, nil, ErrFrameTooShort
	}

	frameType := frameBytes[0]
	seq := binary.BigEndian.Uint32(frameBytes[1:5])
	payloadLen := binary.BigEndian.Uint32(frameBytes[5:9])

	expectedTotal := BinaryFrameHeaderLen + int(payloadLen) + GCMTagLen
	if len(frameBytes) != expectedTotal {
		return 0, 0, nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrFrameLengthMismatch, expectedTotal, len(frameBytes))
	}

	gcm, err := s.getOrInitRespAEAD()
	if err != nil {
		return 0, 0, nil, err
	}

	nonce := computeFrameNonce(s.ResponseIV, seq)
	header := frameBytes[:BinaryFrameHeaderLen]
	ciphertextWithTag := frameBytes[BinaryFrameHeaderLen:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextWithTag, header)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("decrypting frame payload: %w", err)
	}

	return frameType, seq, plaintext, nil
}

// UnwrapBinaryHPKERequest unmarshals and decrypts a strict binary HPKE request envelope.
// Wire format: [ClientEphPub: 32B][Nonce: 12B][Ciphertext + Tag: N >= 16B]
// Returns the decrypted plaintext and the derived HPKESession for response framing.
func UnwrapBinaryHPKERequest(recipientPriv [32]byte, rawBody []byte) ([]byte, *HPKESession, error) {
	if len(rawBody) < MinBinaryRequestLen {
		return nil, nil, ErrPayloadTooShort
	}

	var clientEphPub [32]byte
	copy(clientEphPub[:], rawBody[0:32])
	nonce := rawBody[32:44]
	ciphertext := rawBody[44:]

	// 1. Compute shared secret
	sharedSecret, err := computeX25519SharedSecret(recipientPriv[:], clientEphPub[:])
	if err != nil {
		return nil, nil, err
	}
	defer Zeroize(sharedSecret)

	// 2. Derive request key, response key, and response IV via HKDF-SHA256
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

	// 3. Decrypt request body with AES-256-GCM
	block, err := aes.NewCipher(reqKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting request ciphertext: %w", err)
	}

	session := &HPKESession{
		ClientEphPub: clientEphPub,
		RequestKey:   reqKey,
		ResponseKey:  respKey,
		ResponseIV:   respIV,
		seqNum:       0,
	}
	if _, err := session.getOrInitRespAEAD(); err != nil {
		return nil, nil, fmt.Errorf("initializing response cipher: %w", err)
	}

	return plaintext, session, nil
}

// EncryptBinaryHPKERequest constructs a strict binary HPKE request envelope from the client.
// Returns the binary wire payload and client-side HPKESession for response frame decryption.
func EncryptBinaryHPKERequest(clientPriv [32]byte, recipientPub [32]byte, plaintext []byte) ([]byte, *HPKESession, error) {
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

	out := make([]byte, 32+len(nonce)+len(ciphertext))
	copy(out[0:32], clientPub[:])
	copy(out[32:44], nonce)
	copy(out[44:], ciphertext)

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

	return out, session, nil
}

