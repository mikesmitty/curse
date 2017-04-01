package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type certOpts struct {
	CA        *x509.Certificate
	CAKey     *ecdsa.PrivateKey
	CN        string
	CSR       *x509.CertificateRequest
	IsCA      bool
	PubKey    *ecdsa.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	SAN       string
	Serial    *big.Int
}

func tlsCertFP(c *x509.Certificate) []byte {
	hash := make([]byte, base64.RawStdEncoding.EncodedLen(len(c.Raw)))
	sha256sum := sha256.Sum256(c.Raw)
	base64.RawStdEncoding.Encode(hash, sha256sum[:])
	return hash
}

func tlsGenKey(curve string) ([]byte, *ecdsa.PrivateKey, error) {
	var (
		key *ecdsa.PrivateKey
		err error
	)

	switch curve {
	case "p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("Could not generate TLS key, invalid elliptic curve: %s", curve)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("Error generating TLS key: %v", err)
	}

	// Marshal key and write to disk
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to convert TLS private key format to DER: %v", err)
	}
	pemKey := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	privateKeyPEM := pem.EncodeToMemory(pemKey)

	return privateKeyPEM, key, nil
}

func tlsSignCert(c certOpts) ([]byte, []byte, error) {
	var (
		certBytes []byte
		err       error
		san       []string
		subject   pkix.Name
	)

	// Add the SAN field if we've got it
	if c.SAN != "" {
		san = []string{c.SAN}
	}

	if c.CSR == nil {
		subject = pkix.Name{
			CommonName:   c.CN,
			Organization: []string{"CURSED"},
		}
	} else {
		subject = c.CSR.Subject
	}

	tmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              san,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		NotBefore:             c.NotBefore,
		NotAfter:              c.NotAfter,
		SerialNumber:          c.Serial,
		Subject:               subject,
	}

	if c.IsCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

		certBytes, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &c.CAKey.PublicKey, c.CAKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to create certificate: %v", err)
		}
	} else {
		certBytes, err = x509.CreateCertificate(rand.Reader, tmpl, c.CA, c.CSR.PublicKey, c.CAKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to create certificate: %v", err)
		}
	}

	// Convert to PEM format
	pemCert := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certPem := pem.EncodeToMemory(pemCert)

	return certPem, certBytes, nil
}
