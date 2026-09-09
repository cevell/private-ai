package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cevell/private-ai/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVisibilityManagerDefaultPolicy(t *testing.T) {
	verifier := auth.NewDynamicVerifier()
	vm := NewVisibilityManager(verifier)

	policy := vm.GetPolicy()
	assert.Equal(t, VisibilityPublic, policy.Attestation)
	assert.Equal(t, VisibilityPublic, policy.Certificate)
	assert.Equal(t, VisibilityPublic, policy.Health)
	assert.Equal(t, VisibilityHidden, policy.ProbeEgress)
}

func TestVisibilityManagerPreRegistration(t *testing.T) {
	verifier := auth.NewDynamicVerifier()
	vm := NewVisibilityManager(verifier)

	dummyHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}

	// 1. Attestation allowed pre-registration
	reqAttest := httptest.NewRequest(http.MethodGet, "/v1/attestation", nil)
	recAttest := httptest.NewRecorder()
	vm.GuardNonCritical("attestation", dummyHandler).ServeHTTP(recAttest, reqAttest)
	assert.Equal(t, http.StatusOK, recAttest.Code)

	// 2. Certificate allowed pre-registration
	reqCert := httptest.NewRequest(http.MethodGet, "/v1/attestation/certificate", nil)
	recCert := httptest.NewRecorder()
	vm.GuardNonCritical("certificate", dummyHandler).ServeHTTP(recCert, reqCert)
	assert.Equal(t, http.StatusOK, recCert.Code)

	// 3. Health LOCKED DOWN pre-registration (401 Unauthorized)
	reqHealth := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	recHealth := httptest.NewRecorder()
	vm.GuardNonCritical("health", dummyHandler).ServeHTTP(recHealth, reqHealth)
	assert.Equal(t, http.StatusUnauthorized, recHealth.Code)
	assert.Contains(t, recHealth.Body.String(), "locked down until authorized public key is provisioned at launch")

	// 4. Probe-egress LOCKED DOWN pre-registration (401 Unauthorized)
	reqProbe := httptest.NewRequest(http.MethodPost, "/v1/system/probe-egress", nil)
	recProbe := httptest.NewRecorder()
	vm.GuardNonCritical("probe_egress", dummyHandler).ServeHTTP(recProbe, reqProbe)
	assert.Equal(t, http.StatusUnauthorized, recProbe.Code)
	assert.Contains(t, recProbe.Body.String(), "locked down until authorized public key is provisioned at launch")
}

func TestVisibilityManagerToggles(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := auth.NewEd25519Verifier(pub, 0, 0)

	vm := NewVisibilityManager(verifier)

	dummyHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}

	// 1. Initial health is public -> unauthenticated GET succeeds
	reqHealth := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	recHealth := httptest.NewRecorder()
	vm.GuardNonCritical("health", dummyHandler).ServeHTTP(recHealth, reqHealth)
	assert.Equal(t, http.StatusOK, recHealth.Code)

	// 2. Toggle health to "hidden"
	hiddenStr := "hidden"
	_, err = vm.UpdatePolicy(VisibilityUpdateRequest{Health: &hiddenStr})
	require.NoError(t, err)

	// Unauthenticated health request now blocked with 401
	recHealthBlocked := httptest.NewRecorder()
	vm.GuardNonCritical("health", dummyHandler).ServeHTTP(recHealthBlocked, reqHealth)
	assert.Equal(t, http.StatusUnauthorized, recHealthBlocked.Code)
	assert.Contains(t, recHealthBlocked.Body.String(), "is hidden")
	assert.Contains(t, recHealthBlocked.Body.String(), "health")

	// Authenticated health request succeeds
	nowTs := time.Now().Unix()
	nonce := "visnonce12345678"
	sig := auth.SignPayload(priv, "GET", "/v1/health", "req-vis-1", nowTs, nonce, nil)
	reqHealthAuth := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	reqHealthAuth.Header.Set("Authorization", fmt.Sprintf("Cevell-Ed25519 signature=%s, timestamp=%d, nonce=%s, request_id=%s", sig, nowTs, nonce, "req-vis-1"))

	recHealthAuth := httptest.NewRecorder()
	vm.GuardNonCritical("health", dummyHandler).ServeHTTP(recHealthAuth, reqHealthAuth)
	assert.Equal(t, http.StatusOK, recHealthAuth.Code)

	// 3. Bulk toggle: "all": "hidden"
	_, err = vm.UpdatePolicy(VisibilityUpdateRequest{All: &hiddenStr})
	require.NoError(t, err)
	policy := vm.GetPolicy()
	assert.Equal(t, VisibilityHidden, policy.Attestation)
	assert.Equal(t, VisibilityHidden, policy.Certificate)
	assert.Equal(t, VisibilityHidden, policy.Health)
	assert.Equal(t, VisibilityHidden, policy.ProbeEgress)

	// Attestation now requires auth
	recAttestBlocked := httptest.NewRecorder()
	reqAttest := httptest.NewRequest(http.MethodGet, "/v1/attestation", nil)
	vm.GuardNonCritical("attestation", dummyHandler).ServeHTTP(recAttestBlocked, reqAttest)
	assert.Equal(t, http.StatusUnauthorized, recAttestBlocked.Code)

	// 4. Bulk toggle back: "all": "public"
	publicStr := "public"
	_, err = vm.UpdatePolicy(VisibilityUpdateRequest{All: &publicStr})
	require.NoError(t, err)
	recAttestOpen := httptest.NewRecorder()
	vm.GuardNonCritical("attestation", dummyHandler).ServeHTTP(recAttestOpen, reqAttest)
	assert.Equal(t, http.StatusOK, recAttestOpen.Code)

	// 5. Invalid setting error
	badStr := "invalid_setting"
	_, err = vm.UpdatePolicy(VisibilityUpdateRequest{All: &badStr})
	assert.Error(t, err)
}
