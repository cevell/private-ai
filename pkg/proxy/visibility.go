package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/cevell/private-ai/pkg/auth"
)

// VisibilitySetting represents the visibility level for non-critical endpoints.
type VisibilitySetting string

const (
	VisibilityPublic VisibilitySetting = "public"
	VisibilityHidden VisibilitySetting = "hidden"
)

// VisibilityPolicy defines whether non-critical endpoints allow unauthenticated access ("public")
// or require authorized Ed25519 signatures ("hidden").
type VisibilityPolicy struct {
	Attestation VisibilitySetting `json:"attestation"`
	Certificate VisibilitySetting `json:"certificate"`
	Health      VisibilitySetting `json:"health"`
	ProbeEgress VisibilitySetting `json:"probe_egress"`
}

// VisibilityUpdateRequest represents the JSON payload to update endpoint visibility.
type VisibilityUpdateRequest struct {
	All         *string `json:"all,omitempty"`
	Attestation *string `json:"attestation,omitempty"`
	Certificate *string `json:"certificate,omitempty"`
	Health      *string `json:"health,omitempty"`
	ProbeEgress *string `json:"probe_egress,omitempty"`
}

// VisibilityManager manages dynamic, mutable visibility controls for non-critical endpoints.
type VisibilityManager struct {
	mu       sync.RWMutex
	policy   VisibilityPolicy
	verifier *auth.Ed25519Verifier
}

// NewVisibilityManager initializes a visibility manager with default public discovery.
func NewVisibilityManager(verifier *auth.Ed25519Verifier) *VisibilityManager {
	return &VisibilityManager{
		verifier: verifier,
		policy: VisibilityPolicy{
			Attestation: VisibilityPublic,
			Certificate: VisibilityPublic,
			Health:      VisibilityPublic,
			ProbeEgress: VisibilityHidden,
		},
	}
}

// GetPolicy returns a snapshot of the current visibility policy.
func (vm *VisibilityManager) GetPolicy() VisibilityPolicy {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.policy
}

// UpdatePolicy updates visibility settings for all or individual non-critical endpoints.
func (vm *VisibilityManager) UpdatePolicy(req VisibilityUpdateRequest) (VisibilityPolicy, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	parseSetting := func(val string, name string) (VisibilitySetting, error) {
		s := VisibilitySetting(strings.ToLower(strings.TrimSpace(val)))
		if s != VisibilityPublic && s != VisibilityHidden {
			return "", fmt.Errorf("invalid visibility setting for %s: %q (must be 'public' or 'hidden')", name, val)
		}
		return s, nil
	}

	// Bulk toggle applies to all non-critical endpoints
	if req.All != nil {
		setting, err := parseSetting(*req.All, "all")
		if err != nil {
			return vm.policy, err
		}
		vm.policy.Attestation = setting
		vm.policy.Certificate = setting
		vm.policy.Health = setting
		vm.policy.ProbeEgress = setting
		return vm.policy, nil
	}

	// Granular individual endpoint toggles
	if req.Attestation != nil {
		s, err := parseSetting(*req.Attestation, "attestation")
		if err != nil {
			return vm.policy, err
		}
		vm.policy.Attestation = s
	}

	if req.Certificate != nil {
		s, err := parseSetting(*req.Certificate, "certificate")
		if err != nil {
			return vm.policy, err
		}
		vm.policy.Certificate = s
	}

	if req.Health != nil {
		s, err := parseSetting(*req.Health, "health")
		if err != nil {
			return vm.policy, err
		}
		vm.policy.Health = s
	}

	if req.ProbeEgress != nil {
		s, err := parseSetting(*req.ProbeEgress, "probe_egress")
		if err != nil {
			return vm.policy, err
		}
		vm.policy.ProbeEgress = s
	}

	return vm.policy, nil
}

// GuardNonCritical wraps a non-critical handler (attestation, certificate, health, probe_egress).
// 1. Pre-registration:
//    - "attestation" and "certificate" pass through unauthenticated (for pre-flight silicon auditing).
//    - "health" and all other non-critical endpoints return 401 Unauthorized until key is enrolled.
// 2. Post-registration:
//    - If enclave is sealed OR policy for this endpoint is "hidden":
//      Requires valid Ed25519 signature from enrolled key.
//    - If policy is "public" and enclave is unsealed:
//      Permits unauthenticated access.
func (vm *VisibilityManager) GuardNonCritical(endpointName string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Phase 1: Pre-registration enforcement
		if vm.verifier == nil || !vm.verifier.IsEnrolled() {
			if endpointName == "attestation" || endpointName == "certificate" {
				next(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Enclave is unenrolled. Endpoint %q is locked down until authorized public key is provisioned at launch.", endpointName),
			})
			return
		}

		// Phase 2: Post-registration enforcement
		vm.mu.RLock()
		var setting VisibilitySetting
		switch endpointName {
		case "attestation":
			setting = vm.policy.Attestation
		case "certificate":
			setting = vm.policy.Certificate
		case "health":
			setting = vm.policy.Health
		case "probe_egress":
			setting = vm.policy.ProbeEgress
		default:
			setting = VisibilityHidden
		}
		vm.mu.RUnlock()

		requiresAuth := IsSealed() || setting == VisibilityHidden
		if requiresAuth {
			bodyBytes, err := vm.verifier.VerifyHTTPRequestHeaderFirst(w, r)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				reason := fmt.Sprintf("Endpoint %q is hidden: authentication required", endpointName)
				if IsSealed() {
					reason = "Enclave is sealed: authentication required"
				}
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("%s: %v", reason, err),
				})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		next(w, r)
	}
}
