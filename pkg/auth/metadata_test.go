package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestParsePublicKeyHex(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	hexStr := hex.EncodeToString(pub)

	// 1. Valid 64-char Hex
	parsed, outHex, err := ParsePublicKeyHex(hexStr)
	if err != nil {
		t.Fatalf("ParsePublicKeyHex failed on valid hex: %v", err)
	}
	if outHex != hexStr || !pub.Equal(parsed) {
		t.Errorf("expected %s, got %s", hexStr, outHex)
	}

	// 2. OpenSSH string
	openSSHStr := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEjRWeJq83vASNFZ4mrze8BI0VniavN7wEjRWeJq83v"
	parsedSSH, outHexSSH, err := ParsePublicKeyHex(openSSHStr)
	if err != nil {
		t.Fatalf("ParsePublicKeyHex failed on OpenSSH string: %v", err)
	}
	expectedHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if outHexSSH != expectedHex {
		t.Errorf("expected %s, got %s", expectedHex, outHexSSH)
	}
	if len(parsedSSH) != 32 {
		t.Errorf("expected 32 byte key, got %d", len(parsedSSH))
	}

	// 3. Invalid format
	_, _, err = ParsePublicKeyHex("invalid_key_string")
	if err == nil {
		t.Errorf("expected error on invalid string, got nil")
	}
}

func TestDiscoverAuthorizedPublicKeyEnv(t *testing.T) {
	expectedHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	os.Setenv("CEVELL_AUTH_PUB", expectedHex)
	defer os.Unsetenv("CEVELL_AUTH_PUB")

	pub, hexOut, source, err := DiscoverAuthorizedPublicKey()
	if err != nil {
		t.Fatalf("DiscoverAuthorizedPublicKey failed: %v", err)
	}
	if hexOut != expectedHex {
		t.Errorf("expected %s, got %s", expectedHex, hexOut)
	}
	if len(pub) != 32 {
		t.Errorf("expected 32 bytes pubkey, got %d", len(pub))
	}
	if source != "Environment Variable (CEVELL_AUTH_PUB)" {
		t.Errorf("unexpected source: %s", source)
	}
}

func TestFetchGCPMetadataAttribute(t *testing.T) {
	expectedVal := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/cevell-auth-pub" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(expectedVal))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := server.Client()
	val, err := fetchGCPMetadataAttribute(client, server.URL, "cevell-auth-pub")
	if err != nil {
		t.Fatalf("fetchGCPMetadataAttribute failed: %v", err)
	}
	if val != expectedVal {
		t.Errorf("expected %s, got %s", expectedVal, val)
	}
}
