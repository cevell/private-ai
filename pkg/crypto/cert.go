package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateSelfSignedCert generates a self-signed TLS certificate bound to the given domain and IPs.
func GenerateSelfSignedCert(key *ecdsa.PrivateKey, domain string, extraIPs []net.IP) (*tls.Certificate, []byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial number: %w", err)
	}

	if domain == "" {
		domain = "localhost"
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cevell Confidential Virtual Machine"},
			CommonName:   domain,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain, "cevell-cvm"},
		IPAddresses:           append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, extraIPs...),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := EncodeECDSAPrivateKeyPEM(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("creating tls keypair: %w", err)
	}

	return &tlsCert, certPEM, nil
}
