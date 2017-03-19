package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func genTLSCACert(conf *config) error {
	// Generate CA private key
	caKeyBytes, caKey, err := tlsGenKey(conf.SSLKeyCurve)
	if err != nil {
		return fmt.Errorf("Failed to generate CA private key: %v", err)
	}

	// Set our CA cert validity constraints
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(conf.SSLCADuration) * 24 * time.Hour)

	// Set our serial to 1
	serial := big.NewInt(1)

	// Set our CA cert options
	opts := certOpts{
		CAKey:     caKey,
		CN:        "curse",
		IsBroker:  false,
		IsCA:      true,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		SAN:       conf.SSLCertHostname,
		Serial:    serial,
	}

	// Sign the CA cert
	caCert, _, err := tlsSignCert(opts)
	if err != nil {
		return fmt.Errorf("Failed to generate CA cert: %v", err)
	}

	err = ioutil.WriteFile(conf.SSLKey, caKeyBytes, 0600)
	if err != nil {
		return fmt.Errorf("Failed to write CA private key file: %v", err)
	}

	err = ioutil.WriteFile(conf.SSLCert, caCert, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write cert file: %v", err)
	}
	err = ioutil.WriteFile(conf.SSLCA, caCert, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write CA cert file: %v", err)
	}

	// Update our CA's serial index
	err = setDBSerial(conf, serial)
	if err != nil {
		return err
	}

	return nil
}

func genTLSBrokerCert(conf *config) error {
	// Generate broker private key
	keyBytes, key, err := tlsGenKey(conf.SSLKeyCurve)
	pubKey := key.Public().(*ecdsa.PublicKey)

	// Set our broker cert validity constraints (same as the CA certs)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(conf.SSLCADuration) * 24 * time.Hour)

	// Get the next available serial number
	serial, err := incDBSerial(conf)
	if err != nil {
		return fmt.Errorf("Failed to generate broker cert: %v", err)
	}

	// Set our CA cert options
	opts := certOpts{
		CA:        conf.tlsCACert,
		CAKey:     conf.tlsCAKey,
		CN:        "nginx",
		IsBroker:  true,
		IsCA:      false,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PubKey:    pubKey,
		SAN:       conf.SSLBrokerHostname,
		Serial:    serial,
	}

	// Sign the CA cert
	cert, _, err := tlsSignCert(opts)
	if err != nil {
		return fmt.Errorf("Failed to generate CA cert: %v", err)
	}

	err = ioutil.WriteFile(conf.SSLBrokerKey, keyBytes, 0600)
	if err != nil {
		return fmt.Errorf("Failed to write CA private key file: %v", err)
	}

	err = ioutil.WriteFile(conf.SSLBrokerCert, cert, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write cert file: %v", err)
	}

	return nil
}

func signTLSClientCert(conf *config, csr *x509.CertificateRequest) ([]byte, []byte, error) {
	// Set our broker cert validity constraints (same as the CA certs)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(conf.SSLDuration) * time.Minute)

	// Get the next available serial number
	serial, err := incDBSerial(conf)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate client certficate: %v", err)
	}

	// Set our CA cert options
	opts := certOpts{
		CA:        conf.tlsCACert,
		CAKey:     conf.tlsCAKey,
		CSR:       csr,
		IsBroker:  false,
		IsCA:      false,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Serial:    serial,
	}

	// Sign the CA cert
	pemCert, rawCert, err := tlsSignCert(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate client cert: %v", err)
	}

	return pemCert, rawCert, nil
}

func initTLSCerts(conf *config) (bool, error) {
	var err error

	_, errK := os.Stat(conf.SSLBrokerKey)
	_, errC := os.Stat(conf.SSLBrokerCert)
	if os.IsNotExist(errK) && os.IsNotExist(errC) {
		// Generate CA/server key/cert
		err = genTLSCACert(conf)
		if err != nil {
			return false, err
		}
	}
	if os.IsNotExist(errK) && !os.IsNotExist(errC) {
		return false, fmt.Errorf("Error initializing CA certificate: sslcert exists, but sslkey does not")
	}

	if _, err := os.Stat(conf.SSLCA); os.IsNotExist(err) {
		conf.SSLCA = conf.SSLCert
		return true, fmt.Errorf("Discrete CA cert not supported with automatic cert generation. Using sslcert file as CA cert: %s", conf.SSLCert)
	}

	// Load our CA cert/key for signing
	err = loadTLSCA(conf)
	if err != nil {
		return false, err
	}

	// Check for broker key/cert and generate if necessary
	_, errK = os.Stat(conf.SSLBrokerKey)
	_, errC = os.Stat(conf.SSLBrokerCert)
	if os.IsNotExist(errK) || os.IsNotExist(errC) {
		err = genTLSBrokerCert(conf)
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

func loadTLSCA(conf *config) error {
	// Load CA key for signing
	caKeyPem, err := ioutil.ReadFile(conf.SSLKey)
	if err != nil {
		return fmt.Errorf("Failed to read TLS key file: '%v'", err)
	}
	caKey, _ := pem.Decode(caKeyPem)
	if caKey == nil {
		return fmt.Errorf("Failed to parse TLS key file: '%v'", err)
	}
	conf.tlsCAKey, err = x509.ParseECPrivateKey(caKey.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse TLS cert file: '%v'", err)
	}

	// Load CA cert for signing
	caCertPem, err := ioutil.ReadFile(conf.SSLCert)
	if err != nil {
		return fmt.Errorf("Failed to read TLS cert file: '%v'", err)
	}
	caCert, _ := pem.Decode(caCertPem)
	if caCert == nil {
		return fmt.Errorf("Failed to decode TLS cert file: '%v'", err)
	}
	conf.tlsCACert, err = x509.ParseCertificate(caCert.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse TLS cert file: '%v'", err)
	}

	return nil
}
