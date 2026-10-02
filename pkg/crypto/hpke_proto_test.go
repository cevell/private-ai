package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"testing"

	wirev1 "github.com/cevell/private-ai/pkg/proto/v1"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

func TestProtoHPKE_E2EE_RequestAndResponse(t *testing.T) {
	// 1. Generate CVM server keypair
	var serverPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, serverPriv[:]); err != nil {
		t.Fatalf("failed to generate server private key: %v", err)
	}
	var serverPub [32]byte
	curve25519.ScalarBaseMult(&serverPub, &serverPriv)

	// Attestation binding digest
	mockAttestationDoc := []byte("cevell-attestation-quote-v4-h100")
	attestationHash := sha256.Sum256(mockAttestationDoc)

	// 2. Client encrypts request using EncryptProtoHPKERequest
	var clientPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, clientPriv[:]); err != nil {
		t.Fatalf("failed to generate client private key: %v", err)
	}
	requestPlaintext := []byte(`{"model":"Qwen/Qwen2.5-7B-Instruct","messages":[{"role":"user","content":"Confidential query"}]}`)
	reqProtoBytes, clientSession, err := EncryptProtoHPKERequest(clientPriv, serverPub, requestPlaintext, attestationHash[:], "req-12345")
	if err != nil {
		t.Fatalf("EncryptProtoHPKERequest failed: %v", err)
	}

	// 3. Server unwraps and decrypts request using UnwrapProtoHPKERequest
	decryptedReq, serverSession, protoReq, err := UnwrapProtoHPKERequest(serverPriv, reqProtoBytes, attestationHash[:])
	if err != nil {
		t.Fatalf("UnwrapProtoHPKERequest failed: %v", err)
	}

	if !bytes.Equal(decryptedReq, requestPlaintext) {
		t.Fatalf("decrypted request mismatch: got %s, want %s", string(decryptedReq), string(requestPlaintext))
	}
	if protoReq.RequestId != "req-12345" {
		t.Fatalf("request_id mismatch: got %s, want req-12345", protoReq.RequestId)
	}

	// 4. Server streams frames back to client
	tokens := []string{"Hello", " ", "Confidential", " ", "World!"}
	var encryptedFrames [][]byte
	for _, tok := range tokens {
		frameBytes, err := serverSession.EncryptProtoFrame(wirev1.FrameType_FRAME_TYPE_TOKEN_DELTA, []byte(tok))
		if err != nil {
			t.Fatalf("server failed to encrypt frame: %v", err)
		}
		encryptedFrames = append(encryptedFrames, frameBytes)
	}
	// End frame
	endFrame, err := serverSession.EncryptProtoFrame(wirev1.FrameType_FRAME_TYPE_STREAM_END, []byte("[DONE]"))
	if err != nil {
		t.Fatalf("server failed to encrypt end frame: %v", err)
	}
	encryptedFrames = append(encryptedFrames, endFrame)

	// 5. Client receives and decrypts frames
	for i, frameBytes := range encryptedFrames[:len(tokens)] {
		frameType, seq, decryptedToken, err := clientSession.DecryptProtoFrame(frameBytes)
		if err != nil {
			t.Fatalf("client failed to decrypt frame %d: %v", i, err)
		}
		if frameType != wirev1.FrameType_FRAME_TYPE_TOKEN_DELTA {
			t.Errorf("frame %d type mismatch: got %v, want TOKEN_DELTA", i, frameType)
		}
		if seq != uint32(i) {
			t.Errorf("frame %d sequence mismatch: got %d, want %d", i, seq, i)
		}
		if string(decryptedToken) != tokens[i] {
			t.Errorf("frame %d token mismatch: got %q, want %q", i, string(decryptedToken), tokens[i])
		}
	}

	// Verify end frame
	endType, endSeq, endPayload, err := clientSession.DecryptProtoFrame(encryptedFrames[len(tokens)])
	if err != nil {
		t.Fatalf("client failed to decrypt stream end frame: %v", err)
	}
	if endType != wirev1.FrameType_FRAME_TYPE_STREAM_END {
		t.Errorf("expected STREAM_END frame type, got %v", endType)
	}
	if endSeq != uint32(len(tokens)) {
		t.Errorf("expected end sequence %d, got %d", len(tokens), endSeq)
	}
	if string(endPayload) != "[DONE]" {
		t.Errorf("expected [DONE] payload, got %q", string(endPayload))
	}
}

func TestProtoHPKE_AttestationMismatch_Rejected(t *testing.T) {
	var serverPriv [32]byte
	io.ReadFull(rand.Reader, serverPriv[:])
	var serverPub [32]byte
	curve25519.ScalarBaseMult(&serverPub, &serverPriv)

	var clientPriv [32]byte
	io.ReadFull(rand.Reader, clientPriv[:])

	clientHash := []byte("hash-client-expected-111111111111")
	actualEnclaveHash := []byte("hash-actual-enclave-222222222222")

	reqBytes, _, err := EncryptProtoHPKERequest(clientPriv, serverPub, []byte(`{"test":true}`), clientHash, "req-1")
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	_, _, _, err = UnwrapProtoHPKERequest(serverPriv, reqBytes, actualEnclaveHash)
	if err == nil {
		t.Fatal("expected UnwrapProtoHPKERequest to fail on attestation hash mismatch, but succeeded")
	}
	if err != ErrAttestationMismatch {
		t.Fatalf("expected ErrAttestationMismatch, got: %v", err)
	}
}

func TestProtoHPKE_FrameTampering_Rejected(t *testing.T) {
	var serverPriv [32]byte
	io.ReadFull(rand.Reader, serverPriv[:])
	var serverPub [32]byte
	curve25519.ScalarBaseMult(&serverPub, &serverPriv)

	var clientPriv [32]byte
	io.ReadFull(rand.Reader, clientPriv[:])

	reqBytes, clientSession, err := EncryptProtoHPKERequest(clientPriv, serverPub, []byte(`{}`), nil, "req-1")
	if err != nil {
		t.Fatalf("request encryption failed: %v", err)
	}

	_, serverSession, _, err := UnwrapProtoHPKERequest(serverPriv, reqBytes, nil)
	if err != nil {
		t.Fatalf("server unwrap failed: %v", err)
	}

	frameBytes, err := serverSession.EncryptProtoFrame(wirev1.FrameType_FRAME_TYPE_TOKEN_DELTA, []byte("Secret Token"))
	if err != nil {
		t.Fatalf("frame encryption failed: %v", err)
	}

	// Tamper with ciphertext byte in serialized protobuf
	tamperedFrame := append([]byte(nil), frameBytes...)
	tamperedFrame[len(tamperedFrame)-5] ^= 0xFF

	_, _, _, err = clientSession.DecryptProtoFrame(tamperedFrame)
	if err == nil {
		t.Fatal("expected decryption of tampered frame to fail, but succeeded")
	}
}

func TestProtoHPKE_LowOrderPublicKey_Rejected(t *testing.T) {
	var serverPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, serverPriv[:]); err != nil {
		t.Fatalf("generating server priv: %v", err)
	}

	lowOrderPoints := [][32]byte{
		{},
		{1},
	}

	for _, lowOrder := range lowOrderPoints {
		// 1. EncryptProtoHPKERequest with low-order server public key
		var clientPriv [32]byte
		if _, err := io.ReadFull(rand.Reader, clientPriv[:]); err != nil {
			t.Fatalf("generating client priv: %v", err)
		}
		_, _, err := EncryptProtoHPKERequest(clientPriv, lowOrder, []byte(`{}`), nil, "req-low")
		if !errors.Is(err, ErrLowOrderPublicKey) {
			t.Fatalf("expected ErrLowOrderPublicKey, got %v", err)
		}

		// 2. UnwrapProtoHPKERequest with low-order client public key
		req := &wirev1.EncryptedInferenceRequest{
			Version:                  1,
			CipherSuite:              wirev1.CipherSuite_CIPHER_SUITE_DHKEM_X25519_AES256_GCM,
			ClientEphemeralPublicKey: lowOrder[:],
			Nonce:                    make([]byte, 12),
			EncryptedPayload:         make([]byte, 16),
		}
		rawBytes, err := proto.Marshal(req)
		if err != nil {
			t.Fatalf("marshaling proto: %v", err)
		}
		_, _, _, err = UnwrapProtoHPKERequest(serverPriv, rawBytes, nil)
		_ = serverPriv
		if !errors.Is(err, ErrLowOrderPublicKey) {
			t.Fatalf("expected ErrLowOrderPublicKey, got %v", err)
		}
	}
}

func TestProtoHPKE_KeyReuseDifferentNoncesProducesUniqueResponseKeys(t *testing.T) {
	var serverPriv, serverPub [32]byte
	if _, err := io.ReadFull(rand.Reader, serverPriv[:]); err != nil {
		t.Fatalf("generating server keypair: %v", err)
	}
	curve25519.ScalarBaseMult(&serverPub, &serverPriv)

	var clientPriv, clientPub [32]byte
	if _, err := io.ReadFull(rand.Reader, clientPriv[:]); err != nil {
		t.Fatalf("generating client keypair: %v", err)
	}
	curve25519.ScalarBaseMult(&clientPub, &clientPriv)

	// Two requests using identical client private/public key
	raw1, clientSession1, err := EncryptProtoHPKERequest(clientPriv, serverPub, []byte(`{"prompt":"one"}`), nil, "req-1")
	if err != nil {
		t.Fatalf("encrypting req 1: %v", err)
	}

	raw2, clientSession2, err := EncryptProtoHPKERequest(clientPriv, serverPub, []byte(`{"prompt":"two"}`), nil, "req-2")
	if err != nil {
		t.Fatalf("encrypting req 2: %v", err)
	}

	// Server unwraps both requests
	_, serverSession1, _, err := UnwrapProtoHPKERequest(serverPriv, raw1, nil)
	if err != nil {
		t.Fatalf("unwrapping req 1: %v", err)
	}

	_, serverSession2, _, err := UnwrapProtoHPKERequest(serverPriv, raw2, nil)
	if err != nil {
		t.Fatalf("unwrapping req 2: %v", err)
	}

	// Verify client sessions match server sessions
	if subtle.ConstantTimeCompare(clientSession1.ResponseKey[:], serverSession1.ResponseKey[:]) != 1 {
		t.Fatal("session 1 client/server response key mismatch")
	}
	if subtle.ConstantTimeCompare(clientSession2.ResponseKey[:], serverSession2.ResponseKey[:]) != 1 {
		t.Fatal("session 2 client/server response key mismatch")
	}

	// CRITICAL ASSERTION (Option 2): ResponseKey and ResponseIV MUST be distinct despite identical client key
	if subtle.ConstantTimeCompare(serverSession1.ResponseKey[:], serverSession2.ResponseKey[:]) == 1 {
		t.Fatal("CRITICAL DEFECT: ResponseKey reused across sessions with identical client public key!")
	}
	if subtle.ConstantTimeCompare(serverSession1.ResponseIV[:], serverSession2.ResponseIV[:]) == 1 {
		t.Fatal("CRITICAL DEFECT: ResponseIV reused across sessions with identical client public key!")
	}
}


