package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// KeyPair represents the node's cryptographic identity: TLS ECDSA key and HPKE X25519 key.
type KeyPair struct {
	TLSKey       *ecdsa.PrivateKey
	TLSKeyFP     [32]byte
	HPKEPrivKey  [32]byte
	HPKEPubKey   [32]byte
}

// GenerateNodeKeyPair creates a fresh cryptographic key pair for confidential attestation binding.
func GenerateNodeKeyPair() (*KeyPair, error) {
	// 1. Generate ECDSA P-256 key for TLS
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating TLS ECDSA key: %w", err)
	}

	// Compute SHA-256 fingerprint of the SubjectPublicKeyInfo (SPKI DER)
	derPub, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling TLS public key: %w", err)
	}
	tlsFP := sha256.Sum256(derPub)

	// 2. Generate HPKE X25519 key pair
	var hpkePriv [32]byte
	if _, err := io.ReadFull(rand.Reader, hpkePriv[:]); err != nil {
		return nil, fmt.Errorf("generating HPKE private key: %w", err)
	}

	var hpkePub [32]byte
	curve25519.ScalarBaseMult(&hpkePub, &hpkePriv)

	return &KeyPair{
		TLSKey:      tlsKey,
		TLSKeyFP:    tlsFP,
		HPKEPrivKey: hpkePriv,
		HPKEPubKey:  hpkePub,
	}, nil
}

// EncodeECDSAPrivateKeyPEM serializes an ECDSA private key to PEM format.
func EncodeECDSAPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// GenerateHPKEKeyPair generates a fresh X25519 keypair (priv, pub) for HPKE operations.
func GenerateHPKEKeyPair() ([32]byte, [32]byte, error) {
	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return priv, pub, fmt.Errorf("generating X25519 private key: %w", err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

// Zeroize securely wipes private key material from memory.
func (kp *KeyPair) Zeroize() {
	if kp == nil {
		return
	}
	Zeroize(kp.HPKEPrivKey[:])
	Zeroize(kp.TLSKeyFP[:])
	if kp.TLSKey != nil && kp.TLSKey.D != nil {
		words := kp.TLSKey.D.Bits()
		for i := range words {
			words[i] = 0
		}
		kp.TLSKey.D.SetInt64(0)
	}
}

