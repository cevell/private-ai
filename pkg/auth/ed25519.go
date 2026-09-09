package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMaxClockSkew = 30 * time.Second
	DefaultNonceTTL     = 60 * time.Second
	MaxNonceCacheSize   = 250000
	MaxNonceLength      = 128
)

type nonceEntry struct {
	nonce   string
	addedAt time.Time
}

var (
	ErrMissingSignature   = errors.New("missing ed25519 signature in Authorization header")
	ErrMissingTimestamp   = errors.New("missing X-Cevell-Timestamp in request")
	ErrMissingNonce       = errors.New("missing X-Cevell-Nonce in request")
	ErrInvalidSignature   = errors.New("invalid cryptographic Ed25519 signature")
	ErrTimestampExpired   = errors.New("request timestamp expired or outside allowed clock skew window")
	ErrReplayedNonce      = errors.New("cryptographic nonce has already been consumed (replay attack detected)")
	ErrEnclaveUnenrolled  = errors.New("enclave public key is not enrolled")
	ErrKeyAlreadyEnrolled = errors.New("CVM already has an authorized public key enrolled (single-key invariant)")
	ErrBodyHashMismatch   = errors.New("request body hash does not match signed X-Cevell-Body-SHA256")
	ErrBodyTooLarge       = errors.New("request body exceeds maximum allowed size")
)

// Ed25519Verifier verifies canonical HTTP requests signed by the authorized private key.
type Ed25519Verifier struct {
	keyMu        sync.RWMutex
	publicKey    ed25519.PublicKey
	isEnrolled   bool
	enrolledAt   time.Time
	maxClockSkew time.Duration
	nonceTTL     time.Duration

	nonceMu           sync.Mutex
	seenNonces        map[string]time.Time
	nonceOrder        []nonceEntry
	lastCleanup       time.Time
	maxNonceCacheSize int
}

// NewDynamicVerifier creates a verifier initialized strictly in the unenrolled state.
// All protected endpoints fail closed until a valid public key is registered.
func NewDynamicVerifier() *Ed25519Verifier {
	return &Ed25519Verifier{
		maxClockSkew:      DefaultMaxClockSkew,
		nonceTTL:          DefaultNonceTTL,
		seenNonces:        make(map[string]time.Time),
		nonceOrder:        make([]nonceEntry, 0, 1024),
		lastCleanup:       time.Now(),
		maxNonceCacheSize: MaxNonceCacheSize,
	}
}

// NewDefaultEd25519Verifier returns an Ed25519 verifier initialized with the authorized public key
// discovered at launch from GCP instance metadata (guest-attributes), environment variable, or local key file.
func NewDefaultEd25519Verifier() (*Ed25519Verifier, error) {
	pubKey, _, _, err := DiscoverAuthorizedPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to discover launch-time authorized public key: %w", err)
	}
	return NewEd25519Verifier(pubKey, DefaultMaxClockSkew, DefaultNonceTTL), nil
}

// NewEd25519Verifier initializes a verifier directly in the enrolled state with the specified key (primarily for unit tests).
func NewEd25519Verifier(pubKey ed25519.PublicKey, maxSkew, nonceTTL time.Duration) *Ed25519Verifier {
	if maxSkew <= 0 {
		maxSkew = DefaultMaxClockSkew
	}
	if nonceTTL <= 0 {
		nonceTTL = DefaultNonceTTL
	}
	isEnrolled := len(pubKey) == ed25519.PublicKeySize
	return &Ed25519Verifier{
		publicKey:         pubKey,
		isEnrolled:        isEnrolled,
		enrolledAt:        time.Now(),
		maxClockSkew:      maxSkew,
		nonceTTL:          nonceTTL,
		seenNonces:        make(map[string]time.Time),
		nonceOrder:        make([]nonceEntry, 0, 1024),
		lastCleanup:       time.Now(),
		maxNonceCacheSize: MaxNonceCacheSize,
	}
}

// EnrollKey permanently latches the authorized Ed25519 public key for this CVM.
// Enforces the strict single-key invariant: once enrolled, any subsequent attempts return ErrKeyAlreadyEnrolled.
func (v *Ed25519Verifier) EnrollKey(pubKey ed25519.PublicKey) error {
	v.keyMu.Lock()
	defer v.keyMu.Unlock()

	if v.isEnrolled {
		return ErrKeyAlreadyEnrolled
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(pubKey))
	}

	v.publicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(v.publicKey, pubKey)
	v.isEnrolled = true
	v.enrolledAt = time.Now()
	return nil
}

// IsEnrolled reports whether an authorized public key has been registered.
func (v *Ed25519Verifier) IsEnrolled() bool {
	v.keyMu.RLock()
	defer v.keyMu.RUnlock()
	return v.isEnrolled
}

// GetPublicKey returns a copy of the enrolled public key, or false if unenrolled.
func (v *Ed25519Verifier) GetPublicKey() (ed25519.PublicKey, bool) {
	v.keyMu.RLock()
	defer v.keyMu.RUnlock()
	if !v.isEnrolled {
		return nil, false
	}
	cpy := make(ed25519.PublicKey, len(v.publicKey))
	copy(cpy, v.publicKey)
	return cpy, true
}

// GetPublicKeyHex returns the enrolled public key as a hex string, or empty string if unenrolled.
func (v *Ed25519Verifier) GetPublicKeyHex() string {
	v.keyMu.RLock()
	defer v.keyMu.RUnlock()
	if !v.isEnrolled {
		return ""
	}
	return hex.EncodeToString(v.publicKey)
}

// ParsePublicKey parses an Ed25519 public key strictly from 64-character lowercase hex format or OpenSSH format.
func ParsePublicKey(keyStr string) (ed25519.PublicKey, error) {
	pubKey, _, err := ParsePublicKeyHex(keyStr)
	return pubKey, err
}

// BuildLengthPrefixedCanonicalWithHash constructs a length-prefixed canonical byte slice
// using an explicit bodyHashHex, preventing delimiter collision attacks (CWE-144).
func BuildLengthPrefixedCanonicalWithHash(method, path, requestID, timestampStr, nonce, bodyHashHex string) []byte {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	requestID = strings.TrimSpace(requestID)
	timestampStr = strings.TrimSpace(timestampStr)
	nonce = strings.TrimSpace(nonce)
	bodyHashHex = strings.ToLower(strings.TrimSpace(bodyHashHex))

	var buf bytes.Buffer
	for _, field := range []string{method, path, requestID, timestampStr, nonce, bodyHashHex} {
		fmt.Fprintf(&buf, "%d:%s\n", len(field), field)
	}
	return buf.Bytes()
}

// BuildCanonicalWithHash constructs the colon-delimited byte slice using an explicit bodyHashHex.
// Format: METHOD:PATH:REQUEST_ID:TIMESTAMP:NONCE:BODY_SHA256
func BuildCanonicalWithHash(method, path, requestID, timestampStr, nonce, bodyHashHex string) []byte {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	requestID = strings.TrimSpace(requestID)
	timestampStr = strings.TrimSpace(timestampStr)
	nonce = strings.TrimSpace(nonce)
	bodyHashHex = strings.ToLower(strings.TrimSpace(bodyHashHex))

	canonicalStr := fmt.Sprintf("%s:%s:%s:%s:%s:%s", method, path, requestID, timestampStr, nonce, bodyHashHex)
	return []byte(canonicalStr)
}

// BuildLengthPrefixedCanonicalPayload constructs a length-prefixed canonical byte slice
// preventing delimiter collision attacks (CWE-144).
func BuildLengthPrefixedCanonicalPayload(method, path, requestID, timestampStr, nonce string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	return BuildLengthPrefixedCanonicalWithHash(method, path, requestID, timestampStr, nonce, hex.EncodeToString(bodyHash[:]))
}

// BuildCanonicalPayload constructs the legacy colon-delimited byte slice for signing/verification.
// Format: METHOD:PATH:REQUEST_ID:TIMESTAMP:NONCE:BODY_SHA256
func BuildCanonicalPayload(method, path, requestID, timestampStr, nonce string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	return BuildCanonicalWithHash(method, path, requestID, timestampStr, nonce, hex.EncodeToString(bodyHash[:]))
}

// ExtractAuthHeadersWithBodyHash extracts signature, timestamp, nonce, request_id, and claimed body SHA-256 from standard Cevell headers.
func ExtractAuthHeadersWithBodyHash(r *http.Request) (sig, timestamp, nonce, reqID, bodyHash string) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		authHeader = r.Header.Get("authorization")
	}

	if strings.HasPrefix(strings.ToLower(authHeader), "cevell-ed25519 ") {
		params := strings.TrimSpace(authHeader[15:])
		for _, part := range strings.Split(params, ",") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) == 2 {
				k := strings.ToLower(strings.TrimSpace(kv[0]))
				val := strings.Trim(strings.TrimSpace(kv[1]), "\"")
				switch k {
				case "signature":
					sig = val
				case "timestamp":
					timestamp = val
				case "nonce":
					nonce = val
				case "request_id":
					reqID = val
				case "body_sha256", "sha256":
					bodyHash = strings.ToLower(val)
				}
			}
		}
	} else if strings.HasPrefix(strings.ToLower(authHeader), "ed25519 ") {
		sig = strings.TrimSpace(authHeader[8:])
	} else if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		sig = strings.TrimSpace(authHeader[7:])
	}

	if sig == "" {
		for _, h := range []string{"X-Signature", "x-signature", "X-Cevell-Signature", "x-cevell-signature"} {
			if v := r.Header.Get(h); v != "" {
				sig = v
				break
			}
		}
	}

	if reqID == "" {
		for _, h := range []string{"X-Cevell-Request-ID", "X-Request-ID", "x-request-id", "x-cevell-request-id"} {
			if v := r.Header.Get(h); v != "" {
				reqID = v
				break
			}
		}
	}

	if timestamp == "" {
		for _, h := range []string{"X-Cevell-Timestamp", "X-Timestamp", "x-timestamp", "x-cevell-timestamp"} {
			if v := r.Header.Get(h); v != "" {
				timestamp = v
				break
			}
		}
	}

	if nonce == "" {
		for _, h := range []string{"X-Cevell-Nonce", "X-Nonce", "x-nonce", "x-cevell-nonce"} {
			if v := r.Header.Get(h); v != "" {
				nonce = v
				break
			}
		}
	}

	if bodyHash == "" {
		for _, h := range []string{"X-Cevell-Body-SHA256", "X-Body-SHA256", "x-cevell-body-sha256", "x-body-sha256"} {
			if v := r.Header.Get(h); v != "" {
				bodyHash = strings.ToLower(strings.TrimSpace(v))
				break
			}
		}
	}

	return sig, timestamp, nonce, reqID, bodyHash
}

// ExtractAuthHeaders extracts signature, timestamp, nonce, and request_id from standard Cevell headers.
func ExtractAuthHeaders(r *http.Request) (sig, timestamp, nonce, reqID string) {
	sig, timestamp, nonce, reqID, _ = ExtractAuthHeadersWithBodyHash(r)
	return sig, timestamp, nonce, reqID
}

// VerifyWithBodyHash verifies timestamp freshness, Ed25519 signature, and nonce against an explicit body SHA-256 hash.
// This allows Header-First verification BEFORE reading or buffering any request body in RAM.
func (v *Ed25519Verifier) VerifyWithBodyHash(method, path, requestID, timestampStr, nonce, bodyHashHex, sigB64 string) error {
	v.keyMu.RLock()
	enrolled := v.isEnrolled
	pubKey := v.publicKey
	v.keyMu.RUnlock()

	if !enrolled {
		return ErrEnclaveUnenrolled
	}

	if sigB64 == "" {
		return ErrMissingSignature
	}
	if timestampStr == "" {
		return ErrMissingTimestamp
	}
	if nonce == "" {
		return ErrMissingNonce
	}
	if len(nonce) > MaxNonceLength {
		return fmt.Errorf("nonce exceeds maximum length of %d characters", MaxNonceLength)
	}

	// 1. Parse and check timestamp
	tsInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}
	reqTime := time.Unix(tsInt, 0)
	now := time.Now()

	diff := now.Sub(reqTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > v.maxClockSkew {
		return ErrTimestampExpired
	}

	// 2. Verify signature before recording nonce
	cleanSig := strings.TrimSpace(sigB64)
	sigBytes, err := base64.StdEncoding.DecodeString(cleanSig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature encoding (expected 64-byte base64): %w", ErrInvalidSignature)
	}

	canonicalPrefixed := BuildLengthPrefixedCanonicalWithHash(method, path, requestID, timestampStr, nonce, bodyHashHex)
	canonicalLegacy := BuildCanonicalWithHash(method, path, requestID, timestampStr, nonce, bodyHashHex)
	if !ed25519.Verify(pubKey, canonicalPrefixed, sigBytes) && !ed25519.Verify(pubKey, canonicalLegacy, sigBytes) {
		return ErrInvalidSignature
	}

	// 3. Nonce anti-replay verification
	v.nonceMu.Lock()
	defer v.nonceMu.Unlock()

	maxCap := v.maxNonceCacheSize
	if maxCap <= 0 {
		maxCap = MaxNonceCacheSize
	}

	// Rate-limit periodic cache sweep to at most once per second under load.
	// Because nonceOrder is strictly chronological, expired entries are pruned from the head in O(k).
	if now.Sub(v.lastCleanup) >= time.Second {
		cutoff := now.Add(-v.nonceTTL)
		pruneIdx := 0
		for pruneIdx < len(v.nonceOrder) {
			entry := v.nonceOrder[pruneIdx]
			if entry.addedAt.After(cutoff) {
				break
			}
			delete(v.seenNonces, entry.nonce)
			pruneIdx++
		}
		if pruneIdx > 0 {
			v.nonceOrder = v.nonceOrder[pruneIdx:]
			if cap(v.nonceOrder) > 20000 && len(v.nonceOrder) < cap(v.nonceOrder)/2 {
				compact := make([]nonceEntry, len(v.nonceOrder), len(v.nonceOrder)+1024)
				copy(compact, v.nonceOrder)
				v.nonceOrder = compact
			}
		}
		v.lastCleanup = now
	}

	if _, exists := v.seenNonces[nonce]; exists {
		return ErrReplayedNonce
	}

	// Ring-buffer eviction upon saturation: if cache reaches max capacity,
	// evict the oldest nonces from the head of the order slice.
	// This bounds memory usage while eliminating false 401 rejections under extreme RPS.
	for len(v.seenNonces) >= maxCap && len(v.nonceOrder) > 0 {
		oldest := v.nonceOrder[0]
		v.nonceOrder = v.nonceOrder[1:]
		delete(v.seenNonces, oldest.nonce)
	}

	v.seenNonces[nonce] = now
	v.nonceOrder = append(v.nonceOrder, nonceEntry{nonce: nonce, addedAt: now})

	return nil
}

// Verify checks the signature, timestamp freshness, and nonce uniqueness against the enrolled key.
func (v *Ed25519Verifier) Verify(method, path, requestID, timestampStr, nonce string, body []byte, sigB64 string) error {
	bodyHash := sha256.Sum256(body)
	return v.VerifyWithBodyHash(method, path, requestID, timestampStr, nonce, hex.EncodeToString(bodyHash[:]), sigB64)
}

// VerifyHTTPRequest inspects HTTP request headers and body for valid Ed25519 signature from the enrolled key.
func (v *Ed25519Verifier) VerifyHTTPRequest(r *http.Request, body []byte) error {
	v.keyMu.RLock()
	enrolled := v.isEnrolled
	v.keyMu.RUnlock()

	if !enrolled {
		return ErrEnclaveUnenrolled
	}

	sig, timestamp, nonce, reqID := ExtractAuthHeaders(r)
	return v.Verify(r.Method, r.URL.Path, reqID, timestamp, nonce, body, sig)
}

// VerifyHTTPRequestHeaderFirst performs header-first authentication on an incoming HTTP request.
//
// 1. If an explicit body hash is provided (or if the body is nil/empty):
//    - It extracts the claimed body hash and verifies the Ed25519 signature over
//      canonical headers + claimed body hash FIRST, BEFORE reading r.Body.
//    - If the signature is invalid, it fails immediately with 401, reading ZERO body bytes.
//    - If the signature is valid, it reads the body (bounded by maxBodySize only if > 0),
//      hashes it with SHA-256, and verifies constant_time_compare(claimed_hash, actual_hash) == 1.
//    - If the body hash does not match, it returns ErrBodyHashMismatch (401/400).
//
// 2. If no explicit body hash is provided (legacy client) and body is non-empty:
//    - It reads r.Body (bounded by maxBodySize only if > 0), then verifies the signature.
//
// When maxBodySize is omitted or <= 0, no arbitrary payload size limit is enforced.
// Returns the ingested bodyBytes, and restores r.Body as an io.NopCloser for downstream handlers.
func (v *Ed25519Verifier) VerifyHTTPRequestHeaderFirst(w http.ResponseWriter, r *http.Request, maxBodySize ...int64) ([]byte, error) {
	v.keyMu.RLock()
	enrolled := v.isEnrolled
	v.keyMu.RUnlock()

	if !enrolled {
		return nil, ErrEnclaveUnenrolled
	}

	var limit int64
	if len(maxBodySize) > 0 {
		limit = maxBodySize[0]
	}

	sig, timestamp, nonce, reqID, claimedHash := ExtractAuthHeadersWithBodyHash(r)

	// Determine if body is physically absent or 0-length
	isEmptyBody := r.Body == nil || r.ContentLength == 0
	if claimedHash == "" && isEmptyBody {
		emptyHash := sha256.Sum256(nil)
		claimedHash = hex.EncodeToString(emptyHash[:])
	}

	// Fast Path: Header-First Verification
	// If claimedHash is known (via header or empty body), verify signature BEFORE reading body!
	if claimedHash != "" {
		if err := v.VerifyWithBodyHash(r.Method, r.URL.Path, reqID, timestamp, nonce, claimedHash, sig); err != nil {
			return nil, err
		}

		if isEmptyBody {
			emptyHash := sha256.Sum256(nil)
			emptyHashHex := hex.EncodeToString(emptyHash[:])
			if subtle.ConstantTimeCompare([]byte(strings.ToLower(claimedHash)), []byte(emptyHashHex)) != 1 {
				return nil, ErrBodyHashMismatch
			}
			return nil, nil
		}

		// Signature is verified; now read the body in RAM
		if limit > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) || strings.Contains(err.Error(), "http: request body too large") {
				return nil, ErrBodyTooLarge
			}
			return nil, fmt.Errorf("reading request body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Constant-time check that actual body matches signed hash
		actualHash := sha256.Sum256(bodyBytes)
		actualHashHex := hex.EncodeToString(actualHash[:])
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(claimedHash)), []byte(actualHashHex)) != 1 {
			return nil, ErrBodyHashMismatch
		}

		return bodyBytes, nil
	}

	// Compatibility Fallback: Request with non-empty body and no X-Cevell-Body-SHA256 header.
	// Ingest under MaxBytesReader if limit is configured, then verify signature over the read bytes.
	if limit > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) || strings.Contains(err.Error(), "http: request body too large") {
			return nil, ErrBodyTooLarge
		}
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	if err := v.Verify(r.Method, r.URL.Path, reqID, timestamp, nonce, bodyBytes, sig); err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// ComputeBodyHashHex returns the lowercase 64-character hex SHA-256 digest of a body.
func ComputeBodyHashHex(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// SignPayloadWithBodyHash signs explicitly using a precomputed body SHA-256 hash.
func SignPayloadWithBodyHash(privKey ed25519.PrivateKey, method, path, requestID string, ts int64, nonce, bodyHashHex string) string {
	tsStr := strconv.FormatInt(ts, 10)
	canonical := BuildCanonicalWithHash(method, path, requestID, tsStr, nonce, bodyHashHex)
	sig := ed25519.Sign(privKey, canonical)
	return base64.StdEncoding.EncodeToString(sig)
}

// SignPayload generates an Ed25519 signature string from a private key.
func SignPayload(privKey ed25519.PrivateKey, method, path, requestID string, ts int64, nonce string, body []byte) string {
	tsStr := strconv.FormatInt(ts, 10)
	canonical := BuildCanonicalPayload(method, path, requestID, tsStr, nonce, body)
	sig := ed25519.Sign(privKey, canonical)
	return base64.StdEncoding.EncodeToString(sig)
}

// SignLengthPrefixedPayload generates an Ed25519 base64 signature over the length-prefixed canonical string.
func SignLengthPrefixedPayload(privKey ed25519.PrivateKey, method, path, requestID string, ts int64, nonce string, body []byte) string {
	tsStr := strconv.FormatInt(ts, 10)
	canonical := BuildLengthPrefixedCanonicalPayload(method, path, requestID, tsStr, nonce, body)
	sig := ed25519.Sign(privKey, canonical)
	return base64.StdEncoding.EncodeToString(sig)
}
