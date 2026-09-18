package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/cevell/private-ai/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockModelSupervisor struct {
	ready bool
	model string
}

func (m *mockModelSupervisor) IsReady() bool {
	return m.ready
}

func (m *mockModelSupervisor) CurrentModel() string {
	return m.model
}

func TestSealStateManagement(t *testing.T) {
	SetSealedForTesting(false)
	assert.False(t, IsSealed())

	SetSealedForTesting(true)
	assert.True(t, IsSealed())

	SetSealedForTesting(false)
	assert.False(t, IsSealed())
}

func TestSealAuthGuardTransparentWhenUnsealed(t *testing.T) {
	SetSealedForTesting(false)
	defer SetSealedForTesting(false)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	called := false
	handler := SealAuthGuard(verifier, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSealAuthGuardBlocksWhenSealed(t *testing.T) {
	SetSealedForTesting(true)
	defer SetSealedForTesting(false)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	handler := SealAuthGuard(verifier, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// 1. Unauthenticated request must be blocked with 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)

	assert.Equal(t, http.StatusUnauthorized, recUnauth.Code)
	assert.Contains(t, recUnauth.Body.String(), "Enclave is sealed: authentication required")

	// 2. Authenticated request must succeed with 200
	nowTs := time.Now().Unix()
	nonce := "sealguardnonce01"
	sig := auth.SignPayload(priv, "GET", "/v1/health", "req-guard-1", nowTs, nonce, nil)

	reqAuth := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+sig)
	reqAuth.Header.Set("X-Cevell-Request-ID", "req-guard-1")
	reqAuth.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	reqAuth.Header.Set("X-Cevell-Nonce", nonce)

	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)

	assert.Equal(t, http.StatusOK, recAuth.Code)
	assert.Contains(t, recAuth.Body.String(), `{"status":"ok"}`)
}

func TestSealAuthGuardChunkedTransferValidation(t *testing.T) {
	SetSealedForTesting(true)
	defer SetSealedForTesting(false)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	receivedBody := []byte{}
	handler := SealAuthGuard(verifier, func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	chunkedPayload := []byte(`{"chunked":"test-payload"}`)

	// 1. Attack scenario: client sends chunked payload (ContentLength = -1) but signs empty payload (nil).
	// Must fail with HTTP 401 Unauthorized!
	nowTs := time.Now().Unix()
	nonceAttack := "chunkedattack01"
	sigEmpty := auth.SignPayload(priv, "POST", "/v1/health", "req-chunked-1", nowTs, nonceAttack, nil)

	reqAttack := httptest.NewRequest(http.MethodPost, "/v1/health", bytes.NewReader(chunkedPayload))
	reqAttack.ContentLength = -1 // Simulate Transfer-Encoding: chunked
	reqAttack.Header.Set("Authorization", "Bearer "+sigEmpty)
	reqAttack.Header.Set("X-Cevell-Request-ID", "req-chunked-1")
	reqAttack.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	reqAttack.Header.Set("X-Cevell-Nonce", nonceAttack)

	recAttack := httptest.NewRecorder()
	handler.ServeHTTP(recAttack, reqAttack)
	assert.Equal(t, http.StatusUnauthorized, recAttack.Code)

	// 2. Legitimate scenario: client signs the chunked payload correctly. Must pass with HTTP 200.
	nonceValid := "chunkedvalid01"
	sigValid := auth.SignPayload(priv, "POST", "/v1/health", "req-chunked-2", nowTs, nonceValid, chunkedPayload)

	reqValid := httptest.NewRequest(http.MethodPost, "/v1/health", bytes.NewReader(chunkedPayload))
	reqValid.ContentLength = -1 // Simulate Transfer-Encoding: chunked
	reqValid.Header.Set("Authorization", "Bearer "+sigValid)
	reqValid.Header.Set("X-Cevell-Request-ID", "req-chunked-2")
	reqValid.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	reqValid.Header.Set("X-Cevell-Nonce", nonceValid)

	recValid := httptest.NewRecorder()
	handler.ServeHTTP(recValid, reqValid)
	assert.Equal(t, http.StatusOK, recValid.Code)
	assert.Equal(t, chunkedPayload, receivedBody)
}

func TestRegisterSealEndpoint(t *testing.T) {
	SetSealedForTesting(false)
	defer SetSealedForTesting(false)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	mockSup := &mockModelSupervisor{ready: false, model: "test-qwen"}
	egressCalled := false
	mockEgress := func() error {
		egressCalled = true
		return nil
	}

	mux := http.NewServeMux()
	RegisterSealEndpoint(mux, &SealConfig{
		Verifier:      verifier,
		Supervisor:    mockSup,
		EgressApplier: mockEgress,
	})

	// 1. Method not allowed (GET)
	reqGet := httptest.NewRequest(http.MethodGet, "/v1/system/seal", nil)
	recGet := httptest.NewRecorder()
	mux.ServeHTTP(recGet, reqGet)
	assert.Equal(t, http.StatusMethodNotAllowed, recGet.Code)

	// 2. Unauthenticated POST -> 401
	reqUnauth := httptest.NewRequest(http.MethodPost, "/v1/system/seal", nil)
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	assert.Equal(t, http.StatusUnauthorized, recUnauth.Code)

	// 3. Authenticated POST without ready supervisor -> 412 Precondition Failed
	nowTs := time.Now().Unix()
	nonce1 := "sealtestnonce001"
	sig1 := auth.SignPayload(priv, "POST", "/v1/system/seal", "req-seal-1", nowTs, nonce1, nil)

	reqNotReady := httptest.NewRequest(http.MethodPost, "/v1/system/seal", nil)
	reqNotReady.Header.Set("Authorization", "Bearer "+sig1)
	reqNotReady.Header.Set("X-Cevell-Request-ID", "req-seal-1")
	reqNotReady.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	reqNotReady.Header.Set("X-Cevell-Nonce", nonce1)

	recNotReady := httptest.NewRecorder()
	mux.ServeHTTP(recNotReady, reqNotReady)
	assert.Equal(t, http.StatusPreconditionFailed, recNotReady.Code)
	assert.Contains(t, recNotReady.Body.String(), "Cannot seal: no model is loaded")

	// 4. Authenticated POST with ready supervisor -> 200 OK, triggers egress and latches sealed state
	mockSup.ready = true
	nonce2 := "sealtestnonce002"
	sig2 := auth.SignPayload(priv, "POST", "/v1/system/seal", "req-seal-2", nowTs, nonce2, nil)

	reqReady := httptest.NewRequest(http.MethodPost, "/v1/system/seal", nil)
	reqReady.Header.Set("Authorization", "Bearer "+sig2)
	reqReady.Header.Set("X-Cevell-Request-ID", "req-seal-2")
	reqReady.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	reqReady.Header.Set("X-Cevell-Nonce", nonce2)

	recReady := httptest.NewRecorder()
	mux.ServeHTTP(recReady, reqReady)
	assert.Equal(t, http.StatusOK, recReady.Code)
	assert.True(t, egressCalled)
	assert.True(t, IsSealed())

	var respMap map[string]any
	err = json.Unmarshal(recReady.Body.Bytes(), &respMap)
	require.NoError(t, err)
	assert.Equal(t, "sealed", respMap["status"])
	assert.Equal(t, true, respMap["sealed"])
	assert.Equal(t, "blocked", respMap["outbound_egress"])
	assert.Equal(t, "authenticated_only", respMap["inbound_policy"])
	assert.Equal(t, "test-qwen", respMap["active_model"])

	// 5. Subsequent call is idempotent -> 200 OK with already_sealed
	reqRepeat := httptest.NewRequest(http.MethodPost, "/v1/system/seal", nil)
	recRepeat := httptest.NewRecorder()
	mux.ServeHTTP(recRepeat, reqRepeat)
	assert.Equal(t, http.StatusOK, recRepeat.Code)

	var repeatResp map[string]any
	err = json.Unmarshal(recRepeat.Body.Bytes(), &repeatResp)
	require.NoError(t, err)
	assert.Equal(t, "already_sealed", repeatResp["status"])
	assert.Equal(t, true, repeatResp["sealed"])
}

func TestModelLoadBlockedWhenSealed(t *testing.T) {
	SetSealedForTesting(true)
	defer SetSealedForTesting(false)

	// Simulate handler check
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsSealed() {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Enclave is sealed: model loading is disabled. Terminate and launch a new CVM to load a different model.",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/models/load", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "Enclave is sealed: model loading is disabled")
}

func TestRegisterSealEndpointForceBypassesReadiness(t *testing.T) {
	SetSealedForTesting(false)
	defer SetSealedForTesting(false)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	// Supervisor is NOT ready
	mockSup := &mockModelSupervisor{ready: false, model: "in-flight-model"}
	egressCalled := false
	mockEgress := func() error {
		egressCalled = true
		return nil
	}

	mux := http.NewServeMux()
	RegisterSealEndpoint(mux, &SealConfig{
		Verifier:      verifier,
		Supervisor:    mockSup,
		EgressApplier: mockEgress,
	})

	body := []byte(`{"force": true}`)
	nowTs := time.Now().Unix()
	nonce := "forcenonce12345"
	sig := auth.SignPayload(priv, "POST", "/v1/system/seal", "req-force-1", nowTs, nonce, body)

	req := httptest.NewRequest(http.MethodPost, "/v1/system/seal", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sig)
	req.Header.Set("X-Cevell-Request-ID", "req-force-1")
	req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	req.Header.Set("X-Cevell-Nonce", nonce)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, egressCalled)
	assert.True(t, IsSealed())

	var resp map[string]any
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "sealed", resp["status"])
	assert.Equal(t, true, resp["forced"])
}

func TestRegisterEgressProbeEndpoint(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	mux := http.NewServeMux()
	RegisterEgressProbeEndpoint(mux, verifier)

	// 1. Unauthenticated request -> 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodPost, "/v1/system/probe-egress", nil)
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	assert.Equal(t, http.StatusUnauthorized, recUnauth.Code)

	// 2. Authenticated probe against dummy local listener (supported identically in all modes)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	body, _ := json.Marshal(map[string]any{"target": listener.Addr().String(), "timeout_sec": 1})
	nowTs := time.Now().Unix()
	nonce := "probenonce123456"
	sig := auth.SignPayload(priv, "POST", "/v1/system/probe-egress", "req-probe-1", nowTs, nonce, body)

	reqAuth := httptest.NewRequest(http.MethodPost, "/v1/system/probe-egress", bytes.NewReader(body))
	reqAuth.Header.Set("Authorization", "Bearer "+sig)
	reqAuth.Header.Set("X-Cevell-Request-ID", "req-probe-1")
	reqAuth.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(nowTs, 10))
	reqAuth.Header.Set("X-Cevell-Nonce", nonce)

	recAuth := httptest.NewRecorder()
	mux.ServeHTTP(recAuth, reqAuth)
	assert.Equal(t, http.StatusOK, recAuth.Code)

	var probeResp map[string]any
	err = json.Unmarshal(recAuth.Body.Bytes(), &probeResp)
	require.NoError(t, err)
	assert.Equal(t, "success", probeResp["egress_probe"])
	assert.Equal(t, true, probeResp["internet_accessible"])
}

func TestRegisterEgressProbeEndpointAcceptsLargePayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	vm := NewVisibilityManager(verifier)
	publicStr := "public"
	_, err = vm.UpdatePolicy(VisibilityUpdateRequest{ProbeEgress: &publicStr})
	require.NoError(t, err)

	mux := http.NewServeMux()
	RegisterEgressProbeEndpoint(mux, verifier, vm)

	largePayload := make([]byte, 128*1024) // 128KB > previous 64KB cap
	req := httptest.NewRequest(http.MethodPost, "/v1/system/probe-egress", bytes.NewReader(largePayload))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Must NOT return HTTP 413 Payload Too Large
	assert.NotEqual(t, http.StatusRequestEntityTooLarge, rec.Code)
	_ = priv
}

type trackingBodyReader struct {
	data      []byte
	offset    int
	bytesRead int
}

func (r *trackingBodyReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	r.bytesRead += n
	return n, nil
}

func (r *trackingBodyReader) Close() error {
	return nil
}

func TestSealAuthGuardHeaderFirstZeroByteReadOnInvalidAuth(t *testing.T) {
	SetSealedForTesting(true)
	defer SetSealedForTesting(false)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	handler := SealAuthGuard(verifier, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	body := make([]byte, 1024*1024) // 1MB payload
	bodyHash := auth.ComputeBodyHashHex(body)
	reader := &trackingBodyReader{data: body}

	req := httptest.NewRequest(http.MethodPost, "/v1/health", reader)
	req.Header.Set("Authorization", "Bearer invalid-signature-hex")
	req.Header.Set("X-Cevell-Request-ID", "req-test-hf-1")
	req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Cevell-Nonce", "randomnonce123456")
	req.Header.Set("X-Cevell-Body-SHA256", bodyHash)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, reader.bytesRead, "Expected ZERO body bytes read when invalid signature is rejected header-first")
}

func TestRegisterSealEndpointHeaderFirstZeroByteReadOnInvalidAuth(t *testing.T) {
	SetSealedForTesting(false)
	defer SetSealedForTesting(false)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := auth.NewEd25519Verifier(pub, 30*time.Second, 60*time.Second)

	mux := http.NewServeMux()
	RegisterSealEndpoint(mux, &SealConfig{
		Verifier: verifier,
	})

	body := make([]byte, 1024*1024) // 1MB payload
	bodyHash := auth.ComputeBodyHashHex(body)
	reader := &trackingBodyReader{data: body}

	req := httptest.NewRequest(http.MethodPost, "/v1/system/seal", reader)
	req.Header.Set("Authorization", "Bearer invalid-signature-hex")
	req.Header.Set("X-Cevell-Request-ID", "req-test-hf-2")
	req.Header.Set("X-Cevell-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Cevell-Nonce", "randomnonce654321")
	req.Header.Set("X-Cevell-Body-SHA256", bodyHash)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, reader.bytesRead, "Expected ZERO body bytes read on /v1/system/seal when invalid signature is rejected header-first")
}




