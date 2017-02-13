package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
)

type certConfig struct {
	certType    uint32
	command     string
	duration    time.Duration
	extensions  map[string]string
	keyID       string
	principals  []string
	srcAddr     string
	validAfter  time.Time
	validBefore time.Time
}

func loadCAKey(keyFile string) (ssh.Signer, error) {
	// Read in our private key PEM file
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("Failed to read CA key file: %v", err)
		return nil, err
	}

	sk, err := ssh.ParsePrivateKey(key)
	if err != nil {
		err = fmt.Errorf("Failed to parse CA key: %v", err)
		return nil, err
	}

	return sk, nil
}

func signPubKey(signer ssh.Signer, rawKey []byte, cc certConfig) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(rawKey)
	if err != nil {
		err = fmt.Errorf("Failed to parse pubkey: %v", err)
		return nil, err
	}

	critOpt := make(map[string]string)
	if cc.command != "" {
		critOpt["force-command"] = cc.command
	}
	critOpt["source-address"] = cc.srcAddr

	perms := ssh.Permissions{
		CriticalOptions: critOpt,
		Extensions:      cc.extensions,
	}

	// Make a cert from our pubkey
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          1,
		CertType:        cc.certType,
		KeyId:           cc.keyID,
		ValidPrincipals: cc.principals,
		ValidAfter:      uint64(cc.validAfter.Unix()),
		ValidBefore:     uint64(cc.validBefore.Unix()),
		Permissions:     perms,
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		err = fmt.Errorf("Failed to sign pubkey: %v", err)
		return nil, err
	}

	return cert, err
}
