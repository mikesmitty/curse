package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
)

type certConfig struct {
	certType   uint32
	dur        time.Duration
	exts       map[string]string
	principals []string
	srcAddr    string
}

func loadCAKey(keyFile string) (ssh.Signer, error) {
	// Read in our private key PEM file
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	sk, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

func signPubKey(signer ssh.Signer, rawKey []byte, certConf certConfig) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(rawKey)
	if err != nil {
		err = fmt.Errorf("Failed to parse pubkey: %v", err)
		return nil, err
	}

	// Make a cert from our pubkey
	cert := &ssh.Certificate{
		ValidPrincipals: certConf.principals,
		Key:             pubKey,
		Serial:          1,
		CertType:        certConf.certType,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(certConf.dur).Unix()),
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		err = fmt.Errorf("Failed to sign pubkey: %v", err)
		return nil, err
	}

	return cert, err
}
