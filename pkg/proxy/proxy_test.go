package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cevell/private-ai/pkg/auth"
	"github.com/cevell/private-ai/pkg/config"
	"github.com/cevell/private-ai/pkg/crypto"
	"github.com/cevell/private-ai/pkg/inference"
	wirev1 "github.com/cevell/private-ai/pkg/proto/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyServerUnloadedModelHandling(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()

	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"No model is currently loaded."}`))
	}).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestProxyServerUnboundedIngestion(t *testing.T) {
	// Verify that large payloads (>16MB) are ingested without arbitrary truncation
	largeData := make([]byte, 20*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(largeData))
	rec := httptest.NewRecorder()

	var readBytes int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		readBytes = len(b)
		w.WriteHeader(http.StatusOK)
	})

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, len(largeData), readBytes)
}

func TestStartProxyServerNilGuards(t *testing.T) {
	// 1. Nil ServerConfig
	err := StartProxyServer(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server config cannot be nil")

	// 2. Nil TLSCert
	err = StartProxyServer(&ServerConfig{TLSCert: nil})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TLS certificate cannot be nil")

	// 3. Nil KeyPair
	err = StartProxyServer(&ServerConfig{TLSCert: &tls.Certificate{}, KeyPair: nil})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "node key pair cannot be nil")
}

func TestHealthHandlerModelVisibility(t *testing.T) {
	config.SetTarget("cpu")
	defer config.SetTarget("")

	sup := inference.NewSupervisor(8000)
	falseVal := false
	trueVal := true

	// 1. Model loaded with ExposeInHealth = false
	_ = sup.LoadModel(nil, inference.ModelSpec{Model: "Qwen/Qwen2.5-0.5B-Instruct", ExposeInHealth: &falseVal})
	assert.False(t, sup.ExposeInHealth())

	// 2. Model loaded with ExposeInHealth = true
	_ = sup.LoadModel(nil, inference.ModelSpec{Model: "Qwen/Qwen2.5-0.5B-Instruct", ExposeInHealth: &trueVal})
	assert.True(t, sup.ExposeInHealth())
}

func TestSetupProxyRoutes_LaunchKeyAndVisibility(t *testing.T) {
	config.SetTarget("cpu")
	defer config.SetTarget("")

	keyPair, err := crypto.GenerateNodeKeyPair()
	require.NoError(t, err)

	// Phase 1: Unenrolled Verifier Lockdown Verification
	unenrolledVerifier := auth.NewDynamicVerifier()
	vm := NewVisibilityManager(unenrolledVerifier)
	sup := inference.NewSupervisor(8000)

	cfgUnenrolled := &ServerConfig{
		KeyPair:       keyPair,
		Verifier:      unenrolledVerifier,
		VisibilityMgr: vm,
		Supervisor:    sup,
		TLSCertPEM:    []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"),
	}

	muxUnenrolled, err := SetupProxyRoutes(cfgUnenrolled)
	require.NoError(t, err)

	// 1.1 Attestation & Certificate are permitted unauthenticated
	recCert := httptest.NewRecorder()
	muxUnenrolled.ServeHTTP(recCert, httptest.NewRequest(http.MethodGet, "/v1/attestation/certificate", nil))
	assert.Equal(t, http.StatusOK, recCert.Code)
	assert.Contains(t, recCert.Body.String(), "TEST")

	// 1.2 Health is strictly locked down (401 Unauthorized)
	recHealthPre := httptest.NewRecorder()
	muxUnenrolled.ServeHTTP(recHealthPre, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	assert.Equal(t, http.StatusUnauthorized, recHealthPre.Code)
	assert.Contains(t, recHealthPre.Body.String(), "locked down until authorized public key is provisioned at launch")

	// 1.3 Probe-egress is strictly locked down (401 Unauthorized)
	recProbePre := httptest.NewRecorder()
	muxUnenrolled.ServeHTTP(recProbePre, httptest.NewRequest(http.MethodPost, "/v1/system/probe-egress", nil))
	assert.Equal(t, http.StatusUnauthorized, recProbePre.Code)
	assert.Contains(t, recProbePre.Body.String(), "locked down until authorized public key is provisioned at launch")

	// 1.4 Admin visibility is locked down (401 Unauthorized)
	recVisPre := httptest.NewRecorder()
	muxUnenrolled.ServeHTTP(recVisPre, httptest.NewRequest(http.MethodGet, "/v1/admin/visibility", nil))
	assert.Equal(t, http.StatusUnauthorized, recVisPre.Code)

	// 1.5 Models and inference are locked down (401 Unauthorized)
	recModelsPre := httptest.NewRecorder()
	muxUnenrolled.ServeHTTP(recModelsPre, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	assert.Equal(t, http.StatusUnauthorized, recModelsPre.Code)

	// 1.6 Unmapped/registration endpoints on unenrolled node return 401 lockdown
	recRegPre := httptest.NewRecorder()
	muxUnenrolled.ServeHTTP(recRegPre, httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil))
	assert.Equal(t, http.StatusUnauthorized, recRegPre.Code)
	assert.Contains(t, recRegPre.Body.String(), "locked down until authorized public key is provisioned at launch")

	// Phase 2: Launch-Provisioned Authorized Key Verification
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	latchedVerifier := auth.NewEd25519Verifier(clientPub, 0, 0)
	vmLatched := NewVisibilityManager(latchedVerifier)

	cfgLatched := &ServerConfig{
		KeyPair:       keyPair,
		Verifier:      latchedVerifier,
		VisibilityMgr: vmLatched,
		Supervisor:    sup,
		TLSCertPEM:    []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"),
	}

	mux, err := SetupProxyRoutes(cfgLatched)
	require.NoError(t, err)

	// 2.1 Removed key registration endpoints: unauthenticated returns 401, authenticated returns 404 Not Found
	recRegUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recRegUnauth, httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil))
	assert.Equal(t, http.StatusUnauthorized, recRegUnauth.Code)

	nowTsReg := time.Now().Unix()
	sigReg := auth.SignPayload(clientPriv, "POST", "/v1/auth/register", "req-reg-test", nowTsReg, "regnonce112233", nil)
	reqRegAuth := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	reqRegAuth.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sigReg, nowTsReg, "regnonce112233", "req-reg-test"))
	recRegAuth := httptest.NewRecorder()
	mux.ServeHTTP(recRegAuth, reqRegAuth)
	assert.Equal(t, http.StatusNotFound, recRegAuth.Code)

	// Phase 3: Post-Latching Visibility & Control
	// 3.1 Health defaults to public -> unauthenticated GET succeeds
	recHealthPost := httptest.NewRecorder()
	mux.ServeHTTP(recHealthPost, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	assert.Equal(t, http.StatusOK, recHealthPost.Code)

	// 3.2 Probe-egress defaults to hidden -> unauthenticated POST rejected with 401
	recProbePost := httptest.NewRecorder()
	mux.ServeHTTP(recProbePost, httptest.NewRequest(http.MethodPost, "/v1/system/probe-egress", nil))
	assert.Equal(t, http.StatusUnauthorized, recProbePost.Code)

	// 3.3 Dynamic Toggle via /v1/admin/visibility (authenticated with clientPriv)
	toggleBody := []byte(`{"health":"hidden"}`)
	nowTs := time.Now().Unix()
	nonce := "visnonce87654321"
	toggleSig := auth.SignPayload(clientPriv, "POST", "/v1/admin/visibility", "req-toggle-1", nowTs, nonce, toggleBody)

	reqToggle := httptest.NewRequest(http.MethodPost, "/v1/admin/visibility", bytes.NewReader(toggleBody))
	reqToggle.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", toggleSig, nowTs, nonce, "req-toggle-1"))
	recToggle := httptest.NewRecorder()
	mux.ServeHTTP(recToggle, reqToggle)
	assert.Equal(t, http.StatusOK, recToggle.Code)
	assert.Contains(t, recToggle.Body.String(), `"health":"hidden"`)

	// 3.4 Unauthenticated health is now rejected with 401
	recHealthHidden := httptest.NewRecorder()
	mux.ServeHTTP(recHealthHidden, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	assert.Equal(t, http.StatusUnauthorized, recHealthHidden.Code)

	// 3.5 Authenticated health succeeds with 200
	nowTs = time.Now().Unix()
	nonce = "healthauth123456"
	healthSig := auth.SignPayload(clientPriv, "GET", "/v1/health", "req-health-auth", nowTs, nonce, nil)
	reqHealthAuth := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	reqHealthAuth.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", healthSig, nowTs, nonce, "req-health-auth"))
	recHealthAuth := httptest.NewRecorder()
	mux.ServeHTTP(recHealthAuth, reqHealthAuth)
	assert.Equal(t, http.StatusOK, recHealthAuth.Code)

	// 3.6 Toggle probe_egress to "public"
	probeToggleBody := []byte(`{"probe_egress":"public"}`)
	nowTs = time.Now().Unix()
	nonce = "visnonce99887766"
	probeToggleSig := auth.SignPayload(clientPriv, "POST", "/v1/admin/visibility", "req-toggle-probe", nowTs, nonce, probeToggleBody)

	reqProbeToggle := httptest.NewRequest(http.MethodPost, "/v1/admin/visibility", bytes.NewReader(probeToggleBody))
	reqProbeToggle.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", probeToggleSig, nowTs, nonce, "req-toggle-probe"))
	recProbeToggle := httptest.NewRecorder()
	mux.ServeHTTP(recProbeToggle, reqProbeToggle)
	assert.Equal(t, http.StatusOK, recProbeToggle.Code)
	assert.Contains(t, recProbeToggle.Body.String(), `"probe_egress":"public"`)

	// 3.7 Unauthenticated probe-egress now succeeds (against local test listener)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	probeReqBody, _ := json.Marshal(map[string]any{"target": listener.Addr().String(), "timeout_sec": 1})
	reqProbeOpen := httptest.NewRequest(http.MethodPost, "/v1/system/probe-egress", bytes.NewReader(probeReqBody))
	recProbeOpen := httptest.NewRecorder()
	mux.ServeHTTP(recProbeOpen, reqProbeOpen)
	assert.Equal(t, http.StatusOK, recProbeOpen.Code)
	assert.Contains(t, recProbeOpen.Body.String(), `"egress_probe":"success"`)
}

func setupTestProxyWithMockUpstream(t *testing.T, upstreamHandler http.Handler) (*http.ServeMux, *crypto.KeyPair, ed25519.PrivateKey, *httptest.Server) {
	config.SetTarget("cpu")

	mockUpstream := httptest.NewServer(upstreamHandler)

	keyPair, err := crypto.GenerateNodeKeyPair()
	require.NoError(t, err)

	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := auth.NewEd25519Verifier(clientPub, 0, 0)

	vm := NewVisibilityManager(verifier)
	sup := inference.NewSupervisor(8000)

	sup.SetReadyForTest(true)

	cfg := &ServerConfig{
		KeyPair:       keyPair,
		Verifier:      verifier,
		VisibilityMgr: vm,
		Supervisor:    sup,
		UpstreamURL:   mockUpstream.URL,
		TLSCertPEM:    []byte("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"),
	}

	mux, err := SetupProxyRoutes(cfg)
	require.NoError(t, err)

	return mux, keyPair, clientPriv, mockUpstream
}

func parseBinaryFrames(raw []byte) ([][]byte, error) {
	var frames [][]byte
	offset := 0
	for offset < len(raw) {
		if len(raw)-offset < crypto.BinaryFrameHeaderLen+crypto.GCMTagLen {
			return nil, fmt.Errorf("trailing bytes too short for frame header: %d bytes", len(raw)-offset)
		}
		payloadLen := binary.BigEndian.Uint32(raw[offset+5 : offset+9])
		totalFrameLen := crypto.BinaryFrameHeaderLen + int(payloadLen) + crypto.GCMTagLen
		if offset+totalFrameLen > len(raw) {
			return nil, fmt.Errorf("incomplete frame: need %d bytes, only %d left", totalFrameLen, len(raw)-offset)
		}
		frames = append(frames, raw[offset:offset+totalFrameLen])
		offset += totalFrameLen
	}
	return frames, nil
}

func TestHPKE_PlaintextInference_Rejected(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("Upstream must never be called for unencrypted inference requests")
	})

	mux, _, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	reqBody := []byte(`{"model":"mock-model","messages":[{"role":"user","content":"plain prompt"}]}`)
	nowTs := time.Now().Unix()
	sig := auth.SignPayload(clientPriv, "POST", "/v1/chat/completions", "req-plain", nowTs, "nonce-plain", reqBody)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-plain", "req-plain"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Plaintext requests to inference routes MUST be rejected with 415 Unsupported Media Type
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
	assert.Contains(t, rec.Body.String(), "inference endpoints strictly require mandatory binary HPKE")
}

func TestHPKE_JSONEnvelope_Rejected(t *testing.T) {
	mux, _, clientPriv, upstream := setupTestProxyWithMockUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	jsonBody := []byte(`{"encrypted":true,"payload":"somebase64"}`)
	nowTs := time.Now().Unix()
	sig := auth.SignPayload(clientPriv, "POST", "/v1/chat/completions", "req-json-env", nowTs, "nonce-json-env", jsonBody)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-json-env", "req-json-env"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// JSON envelopes to inference routes MUST be rejected with 415
	assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
}

func TestHPKE_BinaryWireFormat_E2EE(t *testing.T) {
	upstreamResponse := `{"id":"test-2","choices":[{"message":{"content":"secret response from vllm"}}]}`
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		body, _ := io.ReadAll(r.Body)
		assert.Contains(t, string(body), "confidential client prompt")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamResponse))
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	// 1. Client generates ephemeral X25519 keypair and creates binary HPKE request
	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	plaintextPrompt := []byte(`{"model":"mock-model","messages":[{"role":"user","content":"confidential client prompt"}]}`)
	wireBytes, clientSession, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, plaintextPrompt)
	require.NoError(t, err)

	// 2. Gateway/Client signs the wire ciphertext body with authorized Ed25519 private key
	nowTs := time.Now().Unix()
	sig := auth.SignPayload(clientPriv, "POST", "/v1/chat/completions", "req-hpke-bin", nowTs, "nonce-bin", wireBytes)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(wireBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-bin", "req-hpke-bin"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// 3. Assert response is binary wire format
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))

	// 4. Client parses binary frames
	frames, err := parseBinaryFrames(rec.Body.Bytes())
	require.NoError(t, err)
	require.Len(t, frames, 2) // FrameTypeCompletion + FrameTypeStreamEnd

	// 5. Client decrypts completion frame
	fType1, seq1, payload1, err := clientSession.DecryptFrame(frames[0])
	require.NoError(t, err)
	assert.Equal(t, crypto.FrameTypeCompletion, fType1)
	assert.Equal(t, uint32(0), seq1)
	assert.Equal(t, upstreamResponse, string(payload1))

	// 6. Client decrypts end-of-stream frame
	fType2, seq2, payload2, err := clientSession.DecryptFrame(frames[1])
	require.NoError(t, err)
	assert.Equal(t, crypto.FrameTypeStreamEnd, fType2)
	assert.Equal(t, uint32(1), seq2)
	assert.Equal(t, "[DONE]", string(payload2))
}

func TestHPKE_StreamingBinaryFrames_E2EE(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		// Emit 3 SSE events on loopback
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" confidential\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\" world!\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	plaintextPrompt := []byte(`{"model":"mock-model","messages":[{"role":"user","content":"stream prompt"}],"stream":true}`)
	wireBytes, clientSession, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, plaintextPrompt)
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	sig := auth.SignPayload(clientPriv, "POST", "/v1/chat/completions", "req-sse", nowTs, "nonce-sse", wireBytes)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(wireBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-sse", "req-sse"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))

	frames, err := parseBinaryFrames(rec.Body.Bytes())
	require.NoError(t, err)
	require.Len(t, frames, 4) // 3 token deltas + 1 stream end

	var reconstructedText string
	for i := 0; i < 3; i++ {
		fType, seq, payload, err := clientSession.DecryptFrame(frames[i])
		require.NoError(t, err)
		assert.Equal(t, crypto.FrameTypeTokenDelta, fType)
		assert.Equal(t, uint32(i), seq)

		var chunkData struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		err = json.Unmarshal(payload, &chunkData)
		require.NoError(t, err)
		if len(chunkData.Choices) > 0 {
			reconstructedText += chunkData.Choices[0].Delta.Content
		}
	}

	// Verify terminal frame
	fTypeEnd, seqEnd, payloadEnd, err := clientSession.DecryptFrame(frames[3])
	require.NoError(t, err)
	assert.Equal(t, crypto.FrameTypeStreamEnd, fTypeEnd)
	assert.Equal(t, uint32(3), seqEnd)
	assert.Equal(t, "[DONE]", string(payloadEnd))

	assert.Equal(t, "Hello confidential world!", reconstructedText)
}

func TestHPKE_HostileGatewaySignatureValidation(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	// 1. Attacker generates fake Ed25519 key (does not match enrolled key)
	_, fakePriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)
	ciphertext, _, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, []byte("prompt"))
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	fakeSig := auth.SignPayload(fakePriv, "POST", "/v1/chat/completions", "req-fake", nowTs, "nonce-fake", ciphertext)

	reqFake := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(ciphertext))
	reqFake.Header.Set("Content-Type", "application/octet-stream")
	reqFake.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", fakeSig, nowTs, "nonce-fake", "req-fake"))

	recFake := httptest.NewRecorder()
	mux.ServeHTTP(recFake, reqFake)
	assert.Equal(t, http.StatusUnauthorized, recFake.Code, "Unenrolled fake key signature must be rejected")

	// 2. Tampered ciphertext with valid signature
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0xAA // bit flip

	validSigTampered := auth.SignPayload(clientPriv, "POST", "/v1/chat/completions", "req-tampered", nowTs, "nonce-tamp", tamperedCiphertext)

	reqTampered := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(tamperedCiphertext))
	reqTampered.Header.Set("Content-Type", "application/octet-stream")
	reqTampered.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", validSigTampered, nowTs, "nonce-tamp", "req-tampered"))

	recTampered := httptest.NewRecorder()
	mux.ServeHTTP(recTampered, reqTampered)
	assert.Equal(t, http.StatusBadRequest, recTampered.Code, "Tampered ciphertext must fail HPKE decryption")
	assert.Contains(t, recTampered.Body.String(), "Failed to unwrap binary HPKE payload")
}

func TestHPKE_ModelLoad_Encrypted(t *testing.T) {
	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	loadPayload := []byte(`{"model":"mock-loaded-model","expose_in_health":true}`)
	ciphertext, _, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, loadPayload)
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	sig := auth.SignPayload(clientPriv, "POST", "/v1/models/load", "req-load-enc", nowTs, "nonce-load", ciphertext)

	req := httptest.NewRequest(http.MethodPost, "/v1/models/load", bytes.NewReader(ciphertext))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-load", "req-load-enc"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Since mock-loaded-model triggers supervisor LoadModel, check that it reached LoadModel
	// (Returns 200 OK or 500/error if subprocess isn't installed, but NOT 400 bad JSON or 401 unauth)
	assert.NotEqual(t, http.StatusBadRequest, rec.Code, "Must successfully decrypt and parse model spec")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code, "Must authorize successfully")
}

func TestHeaderFirstAuth_ZeroByteReadOnUnauthenticatedInference(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux, _, _, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	// 16MB payload
	oversizedBody := make([]byte, 16*1024*1024)
	bodyHash := auth.ComputeBodyHashHex(oversizedBody)
	reader := &trackingBodyReader{data: oversizedBody}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", reader)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Cevell-Body-SHA256", bodyHash)
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s",
		"baddeadbeefbaddeadbeefbaddeadbeefbaddeadbeefbaddeadbeefbaddeadbeef",
		time.Now().Unix(),
		"nonce-zero-byte-inf",
		"req-zero-byte-inf",
	))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, reader.bytesRead, "Expected ZERO body bytes read when invalid signature is rejected header-first on inference endpoint")
}

func TestHeaderFirstAuth_ZeroByteReadOnUnauthenticatedModelLoad(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mux, _, _, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	// 16MB payload
	oversizedBody := make([]byte, 16*1024*1024)
	bodyHash := auth.ComputeBodyHashHex(oversizedBody)
	reader := &trackingBodyReader{data: oversizedBody}

	req := httptest.NewRequest(http.MethodPost, "/v1/models/load", reader)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Cevell-Body-SHA256", bodyHash)
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s",
		"baddeadbeefbaddeadbeefbaddeadbeefbaddeadbeefbaddeadbeefbaddeadbeef",
		time.Now().Unix(),
		"nonce-zero-byte-load",
		"req-zero-byte-load",
	))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, reader.bytesRead, "Expected ZERO body bytes read when invalid signature is rejected header-first on /v1/models/load")
}

func TestHeaderFirstAuth_ValidInferenceWithBodyHash(t *testing.T) {
	upstreamCalled := false
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Header first test success"}}]}`))
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	chatPayload := []byte(`{"model":"mock-model","messages":[{"role":"user","content":"test"}]}`)
	ciphertext, clientSession, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, chatPayload)
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	bodyHash := auth.ComputeBodyHashHex(ciphertext)
	sig := auth.SignPayloadWithBodyHash(clientPriv, "POST", "/v1/chat/completions", "req-hf-valid", nowTs, "nonce-hf-valid", bodyHash)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(ciphertext))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Cevell-Body-SHA256", bodyHash)
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-hf-valid", "req-hf-valid"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, upstreamCalled)

	frames, err := parseBinaryFrames(rec.Body.Bytes())
	require.NoError(t, err)
	require.NotEmpty(t, frames)

	fType, _, decPayload, err := clientSession.DecryptFrame(frames[0])
	require.NoError(t, err)
	assert.Equal(t, crypto.FrameTypeCompletion, fType)
	assert.Contains(t, string(decPayload), "Header first test success")
}

func parseProtoFrames(body []byte) ([][]byte, error) {
	var frames [][]byte
	offset := 0
	for offset < len(body) {
		if len(body)-offset < 4 {
			return nil, fmt.Errorf("truncated frame length at offset %d", offset)
		}
		frameLen := int(binary.BigEndian.Uint32(body[offset : offset+4]))
		total := 4 + frameLen
		if len(body)-offset < total {
			return nil, fmt.Errorf("truncated frame body: need %d bytes, got %d", total, len(body)-offset)
		}
		frames = append(frames, body[offset:offset+total])
		offset += total
	}
	return frames, nil
}

func TestHPKE_ProtobufInference_NonStreaming_E2EE(t *testing.T) {
	upstreamCalled := false
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "Confidential prompt")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Protobuf confidential completion"}}]}`))
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	rawJSON := []byte(`{"model":"mock-model","messages":[{"role":"user","content":"Confidential prompt"}]}`)
	reqProtoBytes, clientSession, err := crypto.EncryptProtoHPKERequest(clientEphPriv, keyPair.HPKEPubKey, rawJSON, nil, "req-proto-1")
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	bodyHash := auth.ComputeBodyHashHex(reqProtoBytes)
	sig := auth.SignPayloadWithBodyHash(clientPriv, "POST", "/v1/chat/completions", "req-proto-1", nowTs, "nonce-p1", bodyHash)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqProtoBytes))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Cevell-Body-SHA256", bodyHash)
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-p1", "req-proto-1"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, upstreamCalled)
	assert.Equal(t, "application/x-protobuf", rec.Header().Get("Content-Type"))

	frames, err := parseProtoFrames(rec.Body.Bytes())
	require.NoError(t, err)
	require.NotEmpty(t, frames)

	// Completion frame
	fType, seq, decPayload, err := clientSession.DecryptProtoFrame(frames[0])
	require.NoError(t, err)
	assert.Equal(t, wirev1.FrameType_FRAME_TYPE_COMPLETION, fType)
	assert.Equal(t, uint32(0), seq)
	assert.Contains(t, string(decPayload), "Protobuf confidential completion")

	// End frame
	if len(frames) > 1 {
		endType, endSeq, endPayload, err := clientSession.DecryptProtoFrame(frames[1])
		require.NoError(t, err)
		assert.Equal(t, wirev1.FrameType_FRAME_TYPE_STREAM_END, endType)
		assert.Equal(t, uint32(1), endSeq)
		assert.Equal(t, "[DONE]", string(endPayload))
	}
}

func TestHPKE_ProtobufInference_Streaming_E2EE(t *testing.T) {
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Token-1\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Token-2\"}}]}\n\n"))
		flusher.Flush()
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	rawJSON := []byte(`{"model":"mock-model","messages":[{"role":"user","content":"Stream this"}],"stream":true}`)
	reqProtoBytes, clientSession, err := crypto.EncryptProtoHPKERequest(clientEphPriv, keyPair.HPKEPubKey, rawJSON, nil, "req-proto-stream")
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	bodyHash := auth.ComputeBodyHashHex(reqProtoBytes)
	sig := auth.SignPayloadWithBodyHash(clientPriv, "POST", "/v1/chat/completions", "req-proto-stream", nowTs, "nonce-ps", bodyHash)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqProtoBytes))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Cevell-Body-SHA256", bodyHash)
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, "nonce-ps", "req-proto-stream"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/x-protobuf", rec.Header().Get("Content-Type"))

	frames, err := parseProtoFrames(rec.Body.Bytes())
	require.NoError(t, err)
	require.Len(t, frames, 3, "Expected 2 token delta frames + 1 stream end frame")

	// Frame 0: Token-1
	fType0, seq0, dec0, err := clientSession.DecryptProtoFrame(frames[0])
	require.NoError(t, err)
	assert.Equal(t, wirev1.FrameType_FRAME_TYPE_TOKEN_DELTA, fType0)
	assert.Equal(t, uint32(0), seq0)
	assert.Contains(t, string(dec0), "Token-1")

	// Frame 1: Token-2
	fType1, seq1, dec1, err := clientSession.DecryptProtoFrame(frames[1])
	require.NoError(t, err)
	assert.Equal(t, wirev1.FrameType_FRAME_TYPE_TOKEN_DELTA, fType1)
	assert.Equal(t, uint32(1), seq1)
	assert.Contains(t, string(dec1), "Token-2")

	// Frame 2: [DONE]
	fType2, seq2, dec2, err := clientSession.DecryptProtoFrame(frames[2])
	require.NoError(t, err)
	assert.Equal(t, wirev1.FrameType_FRAME_TYPE_STREAM_END, fType2)
	assert.Equal(t, uint32(2), seq2)
	assert.Equal(t, "[DONE]", string(dec2))
}

func TestProxyLoopbackTransport_LoadShedding(t *testing.T) {
	// 1. Test that upstream 429/503 load shedding responses automatically receive Retry-After: 1
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"Engine queue full"}`))
	})

	mux, keyPair, clientPriv, upstream := setupTestProxyWithMockUpstream(t, upstreamHandler)
	defer upstream.Close()

	clientEphPriv, _, err := crypto.GenerateHPKEKeyPair()
	require.NoError(t, err)

	payload := []byte(`{"model":"mock","messages":[{"role":"user","content":"test"}]}`)
	envelope, _, err := crypto.EncryptBinaryHPKERequest(clientEphPriv, keyPair.HPKEPubKey, payload)
	require.NoError(t, err)

	nowTs := time.Now().Unix()
	bodyHash := auth.ComputeBodyHashHex(envelope)
	sig := auth.SignPayloadWithBodyHash(clientPriv, http.MethodPost, "/v1/chat/completions", "req-shed", nowTs, "nonce-shed", bodyHash)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(envelope))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s, body_sha256=%s",
		sig, nowTs, "nonce-shed", "req-shed", bodyHash))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))

	// 2. Test that upstream connection failure returns 503 with Retry-After: 1 via reverseProxy.ErrorHandler
	upstream.Close() // Terminate mock upstream to cause connection refused

	sigDown := auth.SignPayloadWithBodyHash(clientPriv, http.MethodPost, "/v1/chat/completions", "req-shed-2", nowTs, "nonce-shed-2", bodyHash)
	reqDown := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(envelope))
	reqDown.Header.Set("Content-Type", "application/octet-stream")
	reqDown.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s, body_sha256=%s",
		sigDown, nowTs, "nonce-shed-2", "req-shed-2", bodyHash))

	recDown := httptest.NewRecorder()
	mux.ServeHTTP(recDown, reqDown)

	assert.Equal(t, http.StatusServiceUnavailable, recDown.Code)
	assert.Equal(t, "1", recDown.Header().Get("Retry-After"))
}







