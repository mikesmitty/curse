package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func getBrokerFP(conf *config) ([]byte, error) {
	rawCert, err := ioutil.ReadFile(conf.SSLBrokerCert)
	if err != nil {
		return nil, fmt.Errorf("Could not read broker certificate: %v", err)
	}

	certBlock, _ := pem.Decode(rawCert)
	if certBlock == nil {
		return nil, fmt.Errorf("Could not decode broker certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse broker cert: %v", err)
	}

	// Get a public key fingerprint
	fp := tlsCertFP(cert)

	return fp, nil
}

func getTLSConfig(conf *config) (*tls.Config, error) {
	tlsCACert, err := ioutil.ReadFile(conf.SSLCA)
	if err != nil {
		return nil, fmt.Errorf("Could not read sslca certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(tlsCACert); !ok {
		return nil, fmt.Errorf("Could not import sslca certificate: %v", err)
	}

	// Set our TLS config
	tlsConf := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                certPool,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,

		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	tlsConf.BuildNameToCertificate()

	return tlsConf, nil
}
