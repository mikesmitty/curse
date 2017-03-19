package jinxlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func checkTLSCert(conf *config) (bool, bool, error) {
	keyExists := false

	// Check if the client key exists
	if _, err := os.Stat(conf.SSLKeyFile); os.IsNotExist(err) {
		return true, keyExists, fmt.Errorf("TLS key file does not exist")
	}
	keyExists = true

	// Check if the client cert exists
	if _, err := os.Stat(conf.SSLCertFile); os.IsNotExist(err) {
		return true, keyExists, fmt.Errorf("TLS cert file does not exist")
	}

	// Read, decode, and parse the client cert for verification
	certRaw, err := ioutil.ReadFile(conf.SSLCertFile)
	if err != nil {
		return false, keyExists, fmt.Errorf("Failed to read TLS cert file: %v", err)
	}
	certBlock, _ := pem.Decode(certRaw)
	if certBlock == nil {
		return false, keyExists, fmt.Errorf("Failed to decode TLS cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, keyExists, fmt.Errorf("Failed to parse TLS cert: %v", err)
	}

	// Load CA cert for client cert verification
	caBytes, err := ioutil.ReadFile(conf.SSLCAFile)
	if err != nil {
		return false, keyExists, fmt.Errorf("Failed to read TLS CA cert file: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caBytes)

	opts := x509.VerifyOptions{
		Roots:     certPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	_, err = cert.Verify(opts)
	// FIXME need to either trim this or use it
	//if err != nil && err.(type) == x509.CertificateInvalidError && err.Reason == x509.Expired {
	if err != nil {
		return true, keyExists, fmt.Errorf("Failed to verify TLS client cert: %v", err)
	}

	return true, keyExists, nil
}

func genTLSCSR(conf *config) ([]byte, error) {
	// Hard-coding elliptic curve for now, since we control both client and server. This will need
	// to be widened in the future for other key types
	keyRaw, err := ioutil.ReadFile(conf.SSLKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read TLS private key file: %v", err)
	}
	keyBlock, _ := pem.Decode(keyRaw)
	if keyBlock == nil {
		return nil, fmt.Errorf("Failed to decode TLS private key file: %v", err)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse TLS private key: %v", err)
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   conf.userName,
			Organization: []string{"CURSE"},
		},
	}

	publicKey := key.Public()
	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		req.PublicKeyAlgorithm = x509.ECDSA

		switch pub.Curve {
		case elliptic.P256():
			req.SignatureAlgorithm = x509.ECDSAWithSHA256
		case elliptic.P384():
			req.SignatureAlgorithm = x509.ECDSAWithSHA384
		case elliptic.P521():
			req.SignatureAlgorithm = x509.ECDSAWithSHA512
		default:
			req.SignatureAlgorithm = x509.ECDSAWithSHA1
		}
	default:
		return nil, fmt.Errorf("Invalid TLS key type")
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate TLS client CSR: %v", err)
	}

	// Encode our CSR into a PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	csr := pem.EncodeToMemory(pemBlock)

	return csr, nil
}

func genTLSKey(conf *config) ([]byte, error) {
	// Hard-coding elliptic curve for now, since we control both client and server. This will need
	// to be widened in the future for other key types
	var (
		key *ecdsa.PrivateKey
		err error
	)

	switch conf.SSLKeyCurve {
	case "p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("Could not generate TLS client key, invalid elliptic curve: %s", conf.SSLKeyCurve)
	}
	if err != nil {
		return nil, fmt.Errorf("Error generating TLS client key: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to convert TLS private key format to DER: %v", err)
	}

	pemKey := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	privateKeyPEM := pem.EncodeToMemory(pemKey)

	return privateKeyPEM, nil
}

func saveTLSKey(conf *config, keyBytes []byte) error {
	// Create the jinxDir if it doesn't exist
	jinxDir := getPathByFilename(conf.SSLKeyFile)
	if _, err := os.Stat(jinxDir); os.IsNotExist(err) {
		err := os.MkdirAll(jinxDir, 0700)
		if err != nil {
			return fmt.Errorf("Failed to create path to TLS key: %v", err)
		}
	}

	if _, err := os.Stat(conf.SSLKeyFile); os.IsNotExist(err) {
		err := ioutil.WriteFile(conf.SSLKeyFile, keyBytes, 0600)
		if err != nil {
			return fmt.Errorf("Failed to write TLS private key file: %v", err)
		}
	}

	return nil
}
