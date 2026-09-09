package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cevell/private-ai/pkg/system"
)

var (
	// ErrNoPublicKeyFound is returned when no authorized public key could be discovered.
	ErrNoPublicKeyFound = errors.New("no authorized tenant public key discovered in GCP instance metadata, environment, or configuration")

	// ErrInvalidKeyFormat is returned when an extracted public key string cannot be parsed.
	ErrInvalidKeyFormat = errors.New("invalid public key format: must be 64-character hex or OpenSSH ssh-ed25519 string")
)

const (
	GCPMetadataFlavorHeader = "Metadata-Flavor"
	GCPMetadataFlavorValue  = "Google"
	GCPMetadataBaseURL      = "http://metadata.google.internal/computeMetadata/v1/instance/attributes"
	GCPMetadataFallbackURL  = "http://169.254.169.254/computeMetadata/v1/instance/attributes"
)

// ParsePublicKeyHex parses an Ed25519 public key strictly formatted as 64-char lowercase hex
// or extracts the 32 raw public key bytes from an OpenSSH format string (ssh-ed25519 <base64>).
func ParsePublicKeyHex(keyStr string) (ed25519.PublicKey, string, error) {
	clean := strings.TrimSpace(keyStr)
	if clean == "" {
		return nil, "", ErrInvalidKeyFormat
	}

	// 1. Check if OpenSSH format: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
	if strings.HasPrefix(clean, "ssh-ed25519 ") {
		parts := strings.Fields(clean)
		if len(parts) >= 2 {
			b64Key := parts[1]
			raw, err := base64.StdEncoding.DecodeString(b64Key)
			if err == nil {
				// OpenSSH wire format: 4-byte string len + "ssh-ed25519" (11 bytes) + 4-byte key len + 32-byte pubkey
				if len(raw) == 51 && string(raw[4:15]) == "ssh-ed25519" {
					pubKeyBytes := raw[19:51]
					return ed25519.PublicKey(pubKeyBytes), hex.EncodeToString(pubKeyBytes), nil
				}
				// Or raw 32 bytes base64 decoded
				if len(raw) == ed25519.PublicKeySize {
					return ed25519.PublicKey(raw), hex.EncodeToString(raw), nil
				}
			}
		}
	}

	// 2. Strict 64-character Hex format
	if len(clean) == 64 {
		b, err := hex.DecodeString(clean)
		if err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), strings.ToLower(clean), nil
		}
	}

	return nil, "", fmt.Errorf("%w: input does not match 64-character hex or OpenSSH specification (length %d)", ErrInvalidKeyFormat, len(clean))
}

// fetchGCPMetadataAttribute attempts to query a GCP Compute Engine instance attribute.
func fetchGCPMetadataAttribute(client *http.Client, baseURL, attributeName string) (string, error) {
	reqURL := fmt.Sprintf("%s/%s", baseURL, attributeName)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(GCPMetadataFlavorHeader, GCPMetadataFlavorValue)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GCP metadata returned HTTP %d for attribute %s", resp.StatusCode, attributeName)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}

	val := strings.TrimSpace(string(body))
	if val == "" {
		return "", fmt.Errorf("empty attribute %s", attributeName)
	}
	return val, nil
}

// DiscoverAuthorizedPublicKey discovers and resolves the authorized tenant public key
// with the following strict priority:
//  1. Environment Variable `CEVELL_AUTH_PUB` (if explicitly set for local/testing)
//  2. GCP Instance Metadata (`cevell-auth-pub`, `auth-pub`, `ssh-keys`)
//  3. Configuration file `/etc/cevell/auth/auth.pub` or `/mnt/ramdisk/auth.pub`
//
// Returns the parsed ed25519.PublicKey, its canonical 64-character hex string, and origin description.
func DiscoverAuthorizedPublicKey() (ed25519.PublicKey, string, string, error) {
	// 1. Environment Variable check (for local tests / dev mode)
	if envVal := strings.TrimSpace(os.Getenv("CEVELL_AUTH_PUB")); envVal != "" {
		pubKey, hexStr, err := ParsePublicKeyHex(envVal)
		if err == nil {
			return pubKey, hexStr, "Environment Variable (CEVELL_AUTH_PUB)", nil
		}
		system.LogError("CEVELL_AUTH_PUB environment variable parsing failed: %v", err)
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// 2. GCP Instance Metadata query (with retry loop to allow DHCP / link-local routing to settle)
	attributes := []string{"cevell-auth-pub", "auth-pub", "ssh-keys"}
	baseURLs := []string{GCPMetadataFallbackURL, GCPMetadataBaseURL}

	maxAttempts := 10
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		for _, base := range baseURLs {
			for _, attr := range attributes {
				val, err := fetchGCPMetadataAttribute(client, base, attr)
				if err == nil && val != "" {
					pubKey, hexStr, parseErr := ParsePublicKeyHex(val)
					if parseErr == nil {
						source := fmt.Sprintf("GCP Instance Metadata (%s/%s)", base, attr)
						return pubKey, hexStr, source, nil
					}
					system.LogError("Found attribute %s in GCP metadata but parsing failed: %v", attr, parseErr)
				}
			}
		}
		if attempt < maxAttempts {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// 3. Local configuration file fallback
	filePaths := []string{"/etc/cevell/auth/auth.pub", "/mnt/ramdisk/auth.pub", "./configs/auth/auth.pub"}
	for _, fp := range filePaths {
		if data, err := os.ReadFile(fp); err == nil {
			val := strings.TrimSpace(string(data))
			if val != "" {
				pubKey, hexStr, parseErr := ParsePublicKeyHex(val)
				if parseErr == nil {
					return pubKey, hexStr, fmt.Sprintf("Local file (%s)", fp), nil
				}
			}
		}
	}

	return nil, "", "", ErrNoPublicKeyFound
}
