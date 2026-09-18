package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEd25519SignatureVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	body := []byte(`{"model":"Qwen/Qwen2.5-0.5B-Instruct-GGUF"}`)
	method := "POST"
	path := "/v1/models/load"
	reqID := "req-12345"
	nowTs := time.Now().Unix()
	nonce := "a1b2c3d4e5f60718"

	sig := SignPayload(priv, method, path, reqID, nowTs, nonce, body)

	// 1. Valid Signature Test
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), nonce, body, sig)
	assert.NoError(t, err)

	// 2. Replay Nonce Test
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), nonce, body, sig)
	assert.ErrorIs(t, err, ErrReplayedNonce)

	// 3. Tampered Body Test (Invalid signature should NOT burn the nonce)
	nonce2 := "newnonce12345678"
	tamperedBody := []byte(`{"model":"TamperedModel"}`)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), nonce2, tamperedBody, sig)
	assert.ErrorIs(t, err, ErrInvalidSignature)

	// Verify that nonce2 can still be used with valid signature since the invalid attempt did not poison the cache
	validSig2 := SignPayload(priv, method, path, reqID, nowTs, nonce2, body)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), nonce2, body, validSig2)
	assert.NoError(t, err)

	// 4. HTTP Request Middleware Test (Standard Headers)
	nonce3 := "httpnonce1234567"
	sig3 := SignPayload(priv, method, path, reqID, nowTs, nonce3, body)

	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+sig3)
	req.Header.Set("X-Cevell-Request-ID", reqID)
	req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	req.Header.Set("X-Cevell-Nonce", nonce3)

	err = verifier.VerifyHTTPRequest(req, body)
	assert.NoError(t, err)

	// 5. HTTP Request Middleware Test (Cevell-Ed25519 Header)
	nonce4 := "cevellnonce123456"
	sig4 := SignPayload(priv, method, path, reqID, nowTs, nonce4, body)

	req2 := httptest.NewRequest(method, path, nil)
	req2.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig4, nowTs, nonce4, reqID))

	err = verifier.VerifyHTTPRequest(req2, body)
	assert.NoError(t, err)
}

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestDynamicVerifierStartsUnenrolled(t *testing.T) {
	verifier := NewDynamicVerifier()
	assert.False(t, verifier.IsEnrolled())
	pk, ok := verifier.GetPublicKey()
	assert.False(t, ok)
	assert.Nil(t, pk)
	assert.Equal(t, "", verifier.GetPublicKeyHex())

	req := httptest.NewRequest("POST", "/v1/models/load", nil)
	err := verifier.VerifyHTTPRequest(req, []byte(`{}`))
	assert.ErrorIs(t, err, ErrEnclaveUnenrolled)
}

func TestEnrollKeySingleLatch(t *testing.T) {
	verifier := NewDynamicVerifier()
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Invalid key length rejected
	assert.Error(t, verifier.EnrollKey([]byte("short")))

	// First enrollment succeeds
	err = verifier.EnrollKey(pub1)
	assert.NoError(t, err)
	assert.True(t, verifier.IsEnrolled())
	storedPk, ok := verifier.GetPublicKey()
	assert.True(t, ok)
	assert.Equal(t, []byte(pub1), []byte(storedPk))
	assert.Equal(t, hex.EncodeToString(pub1), verifier.GetPublicKeyHex())

	// Second enrollment strictly rejected (Single-Key Invariant)
	err = verifier.EnrollKey(pub2)
	assert.ErrorIs(t, err, ErrKeyAlreadyEnrolled)

	// Stored key remained unchanged
	storedPkAfter, _ := verifier.GetPublicKey()
	assert.Equal(t, []byte(pub1), []byte(storedPkAfter))
}

func TestConcurrentEnrollmentRace(t *testing.T) {
	verifier := NewDynamicVerifier()
	const numGoroutines = 50
	errs := make([]error, numGoroutines)
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			errs[idx] = verifier.EnrollKey(pub)
		}(i)
	}
	wg.Wait()

	successCount := 0
	conflictCount := 0
	for _, err := range errs {
		if err == nil {
			successCount++
		} else if errors.Is(err, ErrKeyAlreadyEnrolled) {
			conflictCount++
		}
	}

	assert.Equal(t, 1, successCount, "Exactly one goroutine must successfully enroll the key")
	assert.Equal(t, numGoroutines-1, conflictCount, "All other concurrent enrollment attempts must return ErrKeyAlreadyEnrolled")
}

func TestParsePublicKey(t *testing.T) {
	// Test ParsePublicKey with valid 64-char hex
	pk, err := ParsePublicKey(testKeyHex)
	require.NoError(t, err)
	assert.Equal(t, testKeyHex, hex.EncodeToString(pk))

	// Test ParsePublicKey rejects non-hex / base64 strings
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	b64Key := base64.StdEncoding.EncodeToString(pub)
	_, err = ParsePublicKey(b64Key)
	assert.Error(t, err, "Base64 encoded public keys must be rejected in favor of strict 64-char hex")

	// Test ParsePublicKey rejects invalid length
	_, err = ParsePublicKey("abcd")
	assert.Error(t, err)
}

func TestNewDefaultEd25519Verifier(t *testing.T) {
	t.Setenv("CEVELL_AUTH_PUB", testKeyHex)

	verifier, err := NewDefaultEd25519Verifier()
	require.NoError(t, err)
	assert.True(t, verifier.IsEnrolled())
	assert.Equal(t, testKeyHex, verifier.GetPublicKeyHex())
}

func TestSignatureEncodingEnforcement(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := NewEd25519Verifier(pub, DefaultMaxClockSkew, DefaultNonceTTL)
	method := "POST"
	path := "/v1/chat/completions"
	reqID := "req-test-123"
	nowTs := time.Now().Unix()
	nonce := "noncetest12345"
	body := []byte(`{"prompt":"hello"}`)

	// 1. Valid Base64 signature
	validB64Sig := SignPayload(priv, method, path, reqID, nowTs, nonce, body)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), nonce, body, validB64Sig)
	assert.NoError(t, err)

	// 2. Malformed Base64 signature
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "newnonce1", body, "not-valid-base64!@#$")
	assert.ErrorIs(t, err, ErrInvalidSignature)

	// 3. Valid Base64 but wrong length (e.g. 32 bytes instead of 64)
	shortBytes := make([]byte, 32)
	shortB64 := base64.StdEncoding.EncodeToString(shortBytes)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "newnonce2", body, shortB64)
	assert.ErrorIs(t, err, ErrInvalidSignature)

	// 4. Hex-encoded signature should be rejected cleanly
	hexSig := hex.EncodeToString([]byte("64_bytes_dummy_signature_data_for_hex_encoding_test_padding_extra"))
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "newnonce3", body, hexSig)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestNonceCacheEvictionAndSaturation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := NewEd25519Verifier(pub, DefaultMaxClockSkew, 50*time.Millisecond)

	method := "POST"
	path := "/v1/chat/completions"
	reqID := "req-evict"
	body := []byte(`{}`)

	// Insert an initial nonce
	nowTs := time.Now().Unix()
	sig1 := SignPayload(priv, method, path, reqID, nowTs, "nonce-expire", body)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "nonce-expire", body, sig1)
	require.NoError(t, err)

	// Verify replay within TTL fails
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "nonce-expire", body, sig1)
	assert.ErrorIs(t, err, ErrReplayedNonce)

	// Wait past TTL + 1s rate limit
	time.Sleep(1100 * time.Millisecond)

	// Verify that a new request triggers eviction and purges expired nonces
	nowTs2 := time.Now().Unix()
	sig2 := SignPayload(priv, method, path, reqID, nowTs2, "nonce-fresh", body)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs2, 10), "nonce-fresh", body, sig2)
	assert.NoError(t, err)

	verifier.nonceMu.Lock()
	_, stillExists := verifier.seenNonces["nonce-expire"]
	verifier.nonceMu.Unlock()
	assert.False(t, stillExists, "Expired nonce should have been purged by periodic sweep")
}

type trackingBodyReader struct {
	data       []byte
	readCalled bool
	offset     int
}

func (r *trackingBodyReader) Read(p []byte) (int, error) {
	r.readCalled = true
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *trackingBodyReader) Close() error {
	return nil
}

func TestHeaderFirstAuth(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := NewEd25519Verifier(pub, DefaultMaxClockSkew, DefaultNonceTTL)

	method := "POST"
	path := "/v1/chat/completions"
	reqID := "req-hf-1"
	nowTs := time.Now().Unix()
	body := []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`)
	bodyHashHex := ComputeBodyHashHex(body)

	t.Run("Valid header-first auth", func(t *testing.T) {
		nonce := "hfnonce01"
		sig := SignPayloadWithBodyHash(priv, method, path, reqID, nowTs, nonce, bodyHashHex)

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+sig)
		req.Header.Set("X-Cevell-Request-ID", reqID)
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)
		req.Header.Set("X-Cevell-Body-SHA256", bodyHashHex)

		rec := httptest.NewRecorder()
		ingested, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req, 16*1024*1024)
		require.NoError(t, err)
		assert.Equal(t, body, ingested)
	})

	t.Run("Invalid signature drops request with ZERO body reads", func(t *testing.T) {
		nonce := "hfnonce02"
		badSig := base64.StdEncoding.EncodeToString(make([]byte, 64))

		tracker := &trackingBodyReader{data: body}
		req := httptest.NewRequest(method, path, tracker)
		req.Header.Set("Authorization", "Bearer "+badSig)
		req.Header.Set("X-Cevell-Request-ID", reqID)
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)
		req.Header.Set("X-Cevell-Body-SHA256", bodyHashHex)

		rec := httptest.NewRecorder()
		_, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req, 16*1024*1024)
		assert.ErrorIs(t, err, ErrInvalidSignature)
		assert.False(t, tracker.readCalled, "Body must NOT be read when header signature fails")
	})

	t.Run("Body hash mismatch rejected", func(t *testing.T) {
		nonce := "hfnonce03"
		sig := SignPayloadWithBodyHash(priv, method, path, reqID, nowTs, nonce, bodyHashHex)

		tamperedBody := []byte(`{"model":"test-model","messages":[{"role":"user","content":"tampered"}]}`)
		req := httptest.NewRequest(method, path, bytes.NewReader(tamperedBody))
		req.Header.Set("Authorization", "Bearer "+sig)
		req.Header.Set("X-Cevell-Request-ID", reqID)
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)
		req.Header.Set("X-Cevell-Body-SHA256", bodyHashHex)

		rec := httptest.NewRecorder()
		_, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req, 16*1024*1024)
		assert.ErrorIs(t, err, ErrBodyHashMismatch)
	})

	t.Run("Empty body authenticated header-first", func(t *testing.T) {
		nonce := "hfnonce04"
		emptyHashHex := ComputeBodyHashHex(nil)
		sig := SignPayloadWithBodyHash(priv, "GET", "/v1/health", "req-hf-get", nowTs, nonce, emptyHashHex)

		req := httptest.NewRequest("GET", "/v1/health", nil)
		req.Header.Set("Authorization", "Bearer "+sig)
		req.Header.Set("X-Cevell-Request-ID", "req-hf-get")
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)

		rec := httptest.NewRecorder()
		ingested, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req, 16*1024*1024)
		require.NoError(t, err)
		assert.Nil(t, ingested)
	})

	t.Run("Empty body with bogus claimed body hash rejected (AUT-03)", func(t *testing.T) {
		nonce := "hfnonce04-bogus"
		bogusHashHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		sig := SignPayloadWithBodyHash(priv, "GET", "/v1/health", "req-hf-bogus", nowTs, nonce, bogusHashHex)

		req := httptest.NewRequest("GET", "/v1/health", nil)
		req.Header.Set("Authorization", "Bearer "+sig)
		req.Header.Set("X-Cevell-Request-ID", "req-hf-bogus")
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)
		req.Header.Set("X-Cevell-Body-SHA256", bogusHashHex)

		rec := httptest.NewRecorder()
		_, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req)
		assert.ErrorIs(t, err, ErrBodyHashMismatch, "Empty body with non-empty claimed hash must be rejected")
	})

	t.Run("Empty body with explicit empty body hash in header succeeds (AUT-03)", func(t *testing.T) {
		nonce := "hfnonce04-valid"
		emptyHashHex := ComputeBodyHashHex(nil)
		sig := SignPayloadWithBodyHash(priv, "GET", "/v1/health", "req-hf-valid", nowTs, nonce, emptyHashHex)

		req := httptest.NewRequest("GET", "/v1/health", nil)
		req.Header.Set("Authorization", "Bearer "+sig)
		req.Header.Set("X-Cevell-Request-ID", "req-hf-valid")
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)
		req.Header.Set("X-Cevell-Body-SHA256", emptyHashHex)

		rec := httptest.NewRecorder()
		ingested, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req)
		require.NoError(t, err)
		assert.Nil(t, ingested)
	})

	t.Run("Body too large rejected when explicit limit set", func(t *testing.T) {
		nonce := "hfnonce05"
		largeBody := make([]byte, 1024)
		largeHashHex := ComputeBodyHashHex(largeBody)
		sig := SignPayloadWithBodyHash(priv, method, path, reqID, nowTs, nonce, largeHashHex)

		req := httptest.NewRequest(method, path, bytes.NewReader(largeBody))
		req.Header.Set("Authorization", "Bearer "+sig)
		req.Header.Set("X-Cevell-Request-ID", reqID)
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)
		req.Header.Set("X-Cevell-Body-SHA256", largeHashHex)

		rec := httptest.NewRecorder()
		_, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req, 512) // Limit 512 bytes < 1024
		assert.ErrorIs(t, err, ErrBodyTooLarge)
	})

	t.Run("Unbounded body read when maxBodySize omitted", func(t *testing.T) {
		nonce := "hfnonce06"
		largeBody := make([]byte, 20*1024*1024) // 20MB payload > previous 16MB cap
		largeHashHex := ComputeBodyHashHex(largeBody)
		sig := SignPayloadWithBodyHash(priv, method, path, reqID, nowTs, nonce, largeHashHex)

		req := httptest.NewRequest(method, path, bytes.NewReader(largeBody))
		req.Header.Set("Authorization", "Bearer "+sig)
		req.Header.Set("X-Cevell-Request-ID", reqID)
		req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
		req.Header.Set("X-Cevell-Nonce", nonce)
		req.Header.Set("X-Cevell-Body-SHA256", largeHashHex)

		rec := httptest.NewRecorder()
		ingested, err := verifier.VerifyHTTPRequestHeaderFirst(rec, req) // No limit specified!
		require.NoError(t, err)
		assert.Equal(t, len(largeBody), len(ingested))
	})
}

func TestNonceCacheRingBufferEviction(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := NewEd25519Verifier(pub, DefaultMaxClockSkew, DefaultNonceTTL)
	verifier.maxNonceCacheSize = 5 // Set small capacity for testing eviction

	method := "POST"
	path := "/v1/chat/completions"
	reqID := "req-ring"
	body := []byte(`{}`)
	nowTs := time.Now().Unix()

	// Insert 5 nonces to reach capacity
	for i := 1; i <= 5; i++ {
		nonce := fmt.Sprintf("nonce-%d", i)
		sig := SignPayload(priv, method, path, reqID, nowTs, nonce, body)
		err := verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), nonce, body, sig)
		require.NoError(t, err)
	}

	// Verify replay on nonce-1 fails
	sig1 := SignPayload(priv, method, path, reqID, nowTs, "nonce-1", body)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "nonce-1", body, sig1)
	assert.ErrorIs(t, err, ErrReplayedNonce)

	// Insert 6th nonce: should NOT error with saturation, should evict nonce-1
	sig6 := SignPayload(priv, method, path, reqID, nowTs, "nonce-6", body)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "nonce-6", body, sig6)
	require.NoError(t, err, "Saturation must not reject legitimate traffic with error")

	verifier.nonceMu.Lock()
	_, nonce1Exists := verifier.seenNonces["nonce-1"]
	_, nonce6Exists := verifier.seenNonces["nonce-6"]
	cacheLen := len(verifier.seenNonces)
	verifier.nonceMu.Unlock()

	assert.False(t, nonce1Exists, "Oldest nonce-1 must be evicted upon saturation")
	assert.True(t, nonce6Exists, "Newest nonce-6 must exist in cache")
	assert.Equal(t, 5, cacheLen, "Cache size must be strictly bounded at maxNonceCacheSize")

	// Verify that replay of nonce-5 (which is still in cache) is still caught
	sig5 := SignPayload(priv, method, path, reqID, nowTs, "nonce-5", body)
	err = verifier.Verify(method, path, reqID, strconv.FormatInt(nowTs, 10), "nonce-5", body, sig5)
	assert.ErrorIs(t, err, ErrReplayedNonce)
}



