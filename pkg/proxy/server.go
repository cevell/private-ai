package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/cevell/private-ai/pkg/attestation"
	"github.com/cevell/private-ai/pkg/auth"
	"github.com/cevell/private-ai/pkg/config"
	"github.com/cevell/private-ai/pkg/crypto"
	"github.com/cevell/private-ai/pkg/inference"
	"github.com/cevell/private-ai/pkg/system"
)

// ServerConfig configures the reverse proxy and attestation server.
type ServerConfig struct {
	Port           int
	UpstreamURL    string
	KeyPair        *crypto.KeyPair
	TLSCert        *tls.Certificate
	TLSCertPEM     []byte
	AttestationDoc *attestation.AttestationDocument
	Supervisor     *inference.Supervisor
	Verifier       *auth.Ed25519Verifier
	VisibilityMgr  *VisibilityManager
}

// SetupProxyRoutes configures all HTTP routes, visibility guards, and reverse proxy handlers.
func SetupProxyRoutes(cfg *ServerConfig) (*http.ServeMux, error) {
	if cfg == nil {
		return nil, errors.New("server config cannot be nil")
	}
	if cfg.KeyPair == nil {
		return nil, errors.New("node key pair cannot be nil")
	}

	mux := http.NewServeMux()

	var ed25519Verifier *auth.Ed25519Verifier
	var err error
	if cfg.Verifier != nil {
		ed25519Verifier = cfg.Verifier
	} else {
		ed25519Verifier, err = auth.NewDefaultEd25519Verifier()
		if err != nil {
			system.LogError("[FATAL SECURITY FAILURE] Failed to initialize Ed25519 verifier: %v", err)
			return nil, fmt.Errorf("failed to initialize Ed25519 verifier: %w", err)
		}
	}

	var visibilityMgr *VisibilityManager
	if cfg.VisibilityMgr != nil {
		visibilityMgr = cfg.VisibilityMgr
	} else {
		visibilityMgr = NewVisibilityManager(ed25519Verifier)
	}

	if cfg.Supervisor == nil {
		cfg.Supervisor = inference.NewSupervisor(8000)
	}

	attestationSem := make(chan struct{}, 4)

	// 1. Primary RESTful Attestation Endpoint: /v1/attestation (Public)
	attestationHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Dynamic Nonce Attestation: ?nonce=<64 hex chars>
		if nonceHex := r.URL.Query().Get("nonce"); nonceHex != "" {
			select {
			case attestationSem <- struct{}{}:
				defer func() { <-attestationSem }()
			default:
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Too many concurrent attestation requests. Please retry shortly.",
				})
				return
			}

			nonceBytes, err := hex.DecodeString(nonceHex)
			if err != nil || len(nonceBytes) != 32 {
				http.Error(w, `{"error":"Invalid nonce: must be 32 bytes (64 hex characters)"}`, http.StatusBadRequest)
				return
			}

			var nonce32 [32]byte
			copy(nonce32[:], nonceBytes)

			gpuEv, _ := attestation.CollectGPUEvidence(nonce32)

			userData := attestation.ComputeCompositeUserData(cfg.KeyPair.TLSKeyFP, cfg.KeyPair.HPKEPubKey, nonce32, gpuEv)

			rawQuote, certChain, platform, err := attestation.FetchHardwareReport(userData)
			if err != nil {
				system.LogError("Hardware attestation failed: %v", err)
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Hardware attestation unavailable: %v", err),
				})
				return
			}

			doc := attestation.BuildAttestationDocumentWithEvidence(attestation.BindingData{
				TLSKeyFingerprint: cfg.KeyPair.TLSKeyFP,
				HPKEPublicKey:     cfg.KeyPair.HPKEPubKey,
			}, rawQuote, certChain, platform, string(cfg.TLSCertPEM), nonceHex, gpuEv)
			doc.Predicate.UserData = hex.EncodeToString(userData[:])

			json.NewEncoder(w).Encode(doc)
			return
		}

		if cfg.AttestationDoc != nil {
			json.NewEncoder(w).Encode(cfg.AttestationDoc)
			return
		}

		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Hardware attestation report is unavailable (hardware or driver not detected)",
		})
	}

	guardedAttestation := visibilityMgr.GuardNonCritical("attestation", attestationHandler)
	mux.HandleFunc("/v1/attestation", guardedAttestation)
	mux.HandleFunc("/.well-known/cevell-attestation", guardedAttestation)
	mux.HandleFunc("/.well-known/attestation", guardedAttestation)

	// 2. Certificate Discovery Endpoint: /v1/attestation/certificate (Toggleable)
	certHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"certificate": string(cfg.TLSCertPEM),
		})
	}
	guardedCert := visibilityMgr.GuardNonCritical("certificate", certHandler)
	mux.HandleFunc("/v1/attestation/certificate", guardedCert)
	mux.HandleFunc("/.well-known/cevell-certificate", guardedCert)

	// 3. Standard Health Check: /v1/health & /health (Toggleable)
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		detectedPlatform := attestation.DetectPlatform()

		// Determine if model identifier may be exposed (explicit opt-in OR authenticated owner with authorized Ed25519 key)
		showModel := cfg.Supervisor.ExposeInHealth()
		if !showModel && ed25519Verifier != nil {
			if err := ed25519Verifier.VerifyHTTPRequest(r, nil); err == nil {
				showModel = true
			}
		}

		if fatalErr := cfg.Supervisor.FatalError(); fatalErr != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			resp := map[string]any{
				"status":   "fatal_hardware_error",
				"error":    fatalErr.Error(),
				"node":     "cevell-cvm",
				"platform": detectedPlatform,
				"ready":    false,
				"backend":  cfg.Supervisor.BackendType(),
				"target":   config.GetTarget(),
			}
			if showModel {
				resp["model"] = cfg.Supervisor.CurrentModel()
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"status":   "ok",
			"node":     "cevell-cvm",
			"platform": detectedPlatform,
			"ready":    cfg.Supervisor.IsReady(),
			"backend":  cfg.Supervisor.BackendType(),
			"target":   config.GetTarget(),
		}
		if showModel {
			resp["model"] = cfg.Supervisor.CurrentModel()
		}
		json.NewEncoder(w).Encode(resp)
	}
	guardedHealth := visibilityMgr.GuardNonCritical("health", healthHandler)
	mux.HandleFunc("/v1/health", guardedHealth)
	mux.HandleFunc("/health", guardedHealth)

	// 4. Enclave Hermetic Seal Endpoint: POST /v1/system/seal (Authenticated with authorized Ed25519 key)
	RegisterSealEndpoint(mux, &SealConfig{
		Verifier:   ed25519Verifier,
		Supervisor: cfg.Supervisor,
	})

	// 5. Diagnostic Egress Probe Endpoint: POST /v1/system/probe-egress (Toggleable with authorized Ed25519 key)
	RegisterEgressProbeEndpoint(mux, ed25519Verifier, visibilityMgr)

	// 6. Dynamic Visibility Management: GET/POST /v1/admin/visibility (Authenticated with authorized Ed25519 key)
	mux.HandleFunc("/v1/admin/visibility", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !ed25519Verifier.IsEnrolled() {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Enclave is unenrolled. Authorized public key must be provisioned at launch.",
			})
			return
		}

		switch r.Method {
		case http.MethodGet:
			if err := ed25519Verifier.VerifyHTTPRequest(r, nil); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Authentication failed: %v", err),
				})
				return
			}
			_ = json.NewEncoder(w).Encode(visibilityMgr.GetPolicy())

		case http.MethodPost:
			bodyBytes, err := ed25519Verifier.VerifyHTTPRequestHeaderFirst(w, r)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Authentication failed: %v", err),
				})
				return
			}

			var req VisibilityUpdateRequest
			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Invalid JSON payload: " + err.Error(),
				})
				return
			}

			updatedPolicy, err := visibilityMgr.UpdatePolicy(req)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": err.Error(),
				})
				return
			}

			system.Log("[VISIBILITY] Visibility policy updated: %+v", updatedPolicy)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "updated",
				"policy": updatedPolicy,
			})

		default:
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	// 6. Dynamic Model Provisioning Endpoint: POST /v1/models/load (Authenticated with authorized Ed25519 key)
	mux.HandleFunc("/v1/models/load", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Block model loading when enclave is sealed (outbound internet access is closed)
		if IsSealed() {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Enclave is sealed: model loading is disabled. Terminate and launch a new CVM to load a different model.",
			})
			return
		}

		// Enforce authorized Ed25519 signature
		if ed25519Verifier == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Authentication verifier is not initialized",
			})
			return
		}

		bodyBytes, err := ed25519Verifier.VerifyHTTPRequestHeaderFirst(w, r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Authentication failed: %v", err),
			})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Unwrap binary HPKE if payload is encrypted with application/octet-stream
		var unwrappedBody []byte = bodyBytes
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.Contains(ct, "application/octet-stream") || strings.Contains(ct, "application/x-cevell-hpke") {
			decrypted, _, err := crypto.UnwrapBinaryHPKERequest(cfg.KeyPair.HPKEPrivKey, bodyBytes)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Failed to unwrap HPKE payload: %v", err),
				})
				return
			}
			unwrappedBody = decrypted
		}

		var spec inference.ModelSpec
		if err := json.Unmarshal(unwrappedBody, &spec); err != nil {
			http.Error(w, `{"error":"Invalid JSON payload"}`, http.StatusBadRequest)
			return
		}

		system.Log("Received authenticated model load request for %s", spec.Model)
		loadCtx, loadCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer loadCancel()
		if err := cfg.Supervisor.LoadModel(loadCtx, spec); err != nil {
			system.LogError("Failed to load model %s: %v", spec.Model, err)
			statusCode := http.StatusInternalServerError
			if strings.Contains(err.Error(), "exceeds maximum viable context length") ||
				strings.Contains(err.Error(), "invalid") ||
				strings.Contains(err.Error(), "required") {
				statusCode = http.StatusBadRequest
			}
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Failed to load model: %v", err),
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "ready",
			"model":          cfg.Supervisor.CurrentModel(),
			"backend":        cfg.Supervisor.BackendType(),
			"max_context":    cfg.Supervisor.MaxContext(),
			"active_context": cfg.Supervisor.ActiveContext(),
		})
	})

	// 5. Authenticated Model List: GET /v1/models (Authenticated with authorized Ed25519 key)
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		if ed25519Verifier == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Authentication verifier is not initialized",
			})
			return
		}
		if err := ed25519Verifier.VerifyHTTPRequest(r, nil); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Authentication failed: %v", err),
			})
			return
		}

		current := cfg.Supervisor.CurrentModel()
		var dataList []map[string]any
		if current != "" {
			dataList = append(dataList, map[string]any{
				"id":             current,
				"object":         "model",
				"created":        time.Now().Unix(),
				"owned_by":       "cevell-cvm",
				"max_context":    cfg.Supervisor.MaxContext(),
				"active_context": cfg.Supervisor.ActiveContext(),
			})
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data":   dataList,
		})
	})

	// 6. Root Handler & In-Enclave Reverse Proxy
	upstream := cfg.UpstreamURL
	if upstream == "" {
		upstreamPort := 8000
		if cfg.Supervisor != nil && cfg.Supervisor.Port() > 0 {
			upstreamPort = cfg.Supervisor.Port()
		}
		upstream = fmt.Sprintf("http://127.0.0.1:%d", upstreamPort)
	}
	upstreamTarget, _ := url.Parse(upstream)
	reverseProxy := httputil.NewSingleHostReverseProxy(upstreamTarget)
	reverseProxy.FlushInterval = 10 * time.Millisecond

	// Dedicated loopback transport with unlimited connection pooling to upstream (127.0.0.1).
	// Standard Go http.DefaultTransport caps idle connections at 2 per host, causing severe
	// socket churn, ephemeral port exhaustion, and TIME_WAIT accumulation under high concurrency.
	reverseProxy.Transport = &http.Transport{
		Proxy: nil, // Loopback traffic never traverses an external proxy
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          0,             // 0 means no limit across all hosts
		MaxIdleConnsPerHost:   math.MaxInt32, // Unlimited idle connections on loopback
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 0,    // Wait for prompt prefill (long context prefills take multi-seconds)
		DisableCompression:    true, // Eliminate compression overhead on internal loopback
	}

	// Fast-fail error handler for upstream inference engine connectivity issues
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			// Client canceled connection; do not write redundant response
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "Inference engine temporarily unavailable or overloaded. Please retry.",
		})
	}

	// Fast-fail relay for engine load shedding: ensure Retry-After header is populated
	reverseProxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if resp.Header.Get("Retry-After") == "" {
				resp.Header.Set("Retry-After", "1")
			}
		}
		return nil
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Pre-registration lockdown: unauthenticated/unmapped requests return 401 until enrolled
		if !ed25519Verifier.IsEnrolled() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Enclave is unenrolled. System is locked down until authorized public key is provisioned at launch.",
			})
			return
		}

		var bodyBytes []byte
		requiresAuth := IsSealed() ||
			strings.HasPrefix(r.URL.Path, "/v1/") ||
			strings.HasPrefix(r.URL.Path, "/tokenize") ||
			strings.HasPrefix(r.URL.Path, "/detokenize")

		if requiresAuth {
			if ed25519Verifier == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "Authentication verifier is not initialized",
				})
				return
			}
			var err error
			bodyBytes, err = ed25519Verifier.VerifyHTTPRequestHeaderFirst(w, r)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Authentication failed: %v", err),
				})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		} else if r.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, `{"error":"Failed to read request body"}`, http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// Check if request is directed to inference endpoints
		isInference := strings.HasPrefix(r.URL.Path, "/v1/chat/completions") ||
			strings.HasPrefix(r.URL.Path, "/v1/completions") ||
			strings.HasPrefix(r.URL.Path, "/v1/embeddings") ||
			strings.HasPrefix(r.URL.Path, "/tokenize") ||
			strings.HasPrefix(r.URL.Path, "/detokenize")

		if isInference {
			// 1. Enforce strict mandatory encrypted Content-Type (no plaintext JSON, no text/event-stream)
			ct := strings.ToLower(r.Header.Get("Content-Type"))
			if !strings.Contains(ct, "application/octet-stream") &&
				!strings.Contains(ct, "application/x-cevell-hpke") &&
				!strings.Contains(ct, "application/x-protobuf") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnsupportedMediaType)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Unsupported media type %q: inference endpoints strictly require mandatory binary HPKE with Content-Type: application/x-protobuf or application/octet-stream", r.Header.Get("Content-Type")),
				})
				return
			}

			// 2. Unwrap HPKE payload (Protobuf or raw binary envelope) - strictly fails on missing or invalid encryption
			var bindingHash []byte
			if cfg.AttestationDoc != nil && len(cfg.AttestationDoc.Predicate.UserData) > 0 {
				h := sha256.Sum256([]byte(cfg.AttestationDoc.Predicate.UserData))
				bindingHash = h[:]
			}
			unwrappedBody, hpkeCtx, err := UnwrapHPKERequest(cfg.KeyPair.HPKEPrivKey, bodyBytes, r.Header.Get("Content-Type"), bindingHash)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Failed to unwrap binary HPKE payload: %v", err),
				})
				return
			}

			if hpkeCtx == nil || hpkeCtx.Session == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Missing mandatory HPKE encryption session",
				})
				return
			}

			// 3. Route inference endpoints to backend inference engine if model is loaded and ready
			if !cfg.Supervisor.IsReady() {
				hpkeCtx.Session.Zeroize()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "No model is currently loaded. Please load a model using POST /v1/models/load with an authorized Ed25519 signature.",
				})
				return
			}

			// 4. Forward decrypted inner payload to loopback vLLM and wrap response in encrypted frames
			r.Body = io.NopCloser(bytes.NewReader(unwrappedBody))
			r.ContentLength = int64(len(unwrappedBody))
			r.Header.Set("Content-Length", fmt.Sprintf("%d", len(unwrappedBody)))
			r.Header.Set("Content-Type", "application/json")

			isProto := false
			if hpkeCtx != nil && hpkeCtx.IsProtobuf {
				isProto = true
			}
			if cfg.Supervisor != nil {
				cfg.Supervisor.RecordActivity()
			}
			hpkeWriter := newHPKEResponseWriter(w, hpkeCtx.Session, isProto)
			if cfg.Supervisor != nil {
				hpkeWriter.onActivity = cfg.Supervisor.RecordActivity
			}
			defer func() {
				if cfg.Supervisor != nil {
					cfg.Supervisor.RecordActivity()
				}
				hpkeWriter.Finish()
			}()

			reverseProxy.ServeHTTP(hpkeWriter, r)
			return
		}

		http.NotFound(w, r)
	})

	return mux, nil
}

// StartProxyServer starts the confidential HTTP/HTTPS server with reverse proxy and attestation endpoints.
func StartProxyServer(cfg *ServerConfig) error {
	if cfg == nil {
		return errors.New("server config cannot be nil")
	}
	if cfg.TLSCert == nil {
		return errors.New("TLS certificate cannot be nil")
	}
	if cfg.KeyPair == nil {
		return errors.New("node key pair cannot be nil")
	}

	mux, err := SetupProxyRoutes(cfg)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*cfg.TLSCert},
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      0, // Disable hard write deadline to allow long-running SSE token streams
		IdleTimeout:       120 * time.Second,
	}

	return server.ListenAndServeTLS("", "")
}
