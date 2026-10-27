package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidProofOfPossession is returned when the proof-of-possession signature verification fails.
	ErrInvalidProofOfPossession = errors.New("invalid cryptographic proof-of-possession signature")
)

// VerifyProofOfPossession cryptographically validates that the registration request was signed
// by the private key matching candidatePubKey, without mutating the verifier's enrollment state.
func (v *Ed25519Verifier) VerifyProofOfPossession(candidatePubKey ed25519.PublicKey, r *http.Request, body []byte) error {
	if len(candidatePubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid candidate public key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(candidatePubKey))
	}

	sig, timestampStr, nonce, reqID, bodyHashHex := ExtractAuthHeadersWithBodyHash(r)
	if sig == "" {
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

	// 1. Validate timestamp freshness
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

	// 2. Decode signature
	cleanSig := strings.TrimSpace(sig)
	sigBytes, err := base64.StdEncoding.DecodeString(cleanSig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature encoding (expected 64-byte base64): %w", ErrInvalidSignature)
	}

	// 3. Compute body hash if not explicitly provided in headers
	if bodyHashHex == "" {
		h := sha256.Sum256(body)
		bodyHashHex = hex.EncodeToString(h[:])
	}

	// 4. Verify signature using candidatePubKey over both canonical formats (with body hash and raw body)
	canonicalPrefixedHash := BuildLengthPrefixedCanonicalWithHash(r.Method, r.URL.Path, reqID, timestampStr, nonce, bodyHashHex)
	canonicalLegacyHash := BuildCanonicalWithHash(r.Method, r.URL.Path, reqID, timestampStr, nonce, bodyHashHex)
	canonicalPrefixed := BuildLengthPrefixedCanonicalPayload(r.Method, r.URL.Path, reqID, timestampStr, nonce, body)
	canonicalLegacy := BuildCanonicalPayload(r.Method, r.URL.Path, reqID, timestampStr, nonce, body)

	if !ed25519.Verify(candidatePubKey, canonicalPrefixedHash, sigBytes) &&
		!ed25519.Verify(candidatePubKey, canonicalLegacyHash, sigBytes) &&
		!ed25519.Verify(candidatePubKey, canonicalPrefixed, sigBytes) &&
		!ed25519.Verify(candidatePubKey, canonicalLegacy, sigBytes) {
		return ErrInvalidProofOfPossession
	}

	// 5. Nonce anti-replay verification
	v.nonceMu.Lock()
	defer v.nonceMu.Unlock()

	maxCap := v.maxNonceCacheSize
	if maxCap <= 0 {
		maxCap = MaxNonceCacheSize
	}

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
		}
		v.lastCleanup = now
	}

	if _, exists := v.seenNonces[nonce]; exists {
		return ErrReplayedNonce
	}

	for len(v.seenNonces) >= maxCap && len(v.nonceOrder) > 0 {
		oldest := v.nonceOrder[0]
		v.nonceOrder = v.nonceOrder[1:]
		delete(v.seenNonces, oldest.nonce)
	}

	v.seenNonces[nonce] = now
	v.nonceOrder = append(v.nonceOrder, nonceEntry{nonce: nonce, addedAt: now})

	return nil
}
