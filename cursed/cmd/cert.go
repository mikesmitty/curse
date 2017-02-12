package cmd

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
)

type certConfig struct {
	certType   uint32
	command    string
	duration   time.Duration
	extensions map[string]string
	keyId      string
	principals []string
	srcAddr    string
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

func signPubKey(signer ssh.Signer, rawKey []byte, certConf certConfig) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(rawKey)
	if err != nil {
		err = fmt.Errorf("Failed to parse pubkey: %v", err)
		return nil, err
	}

	critOpt := make(map[string]string)
	critOpt["force-command"] = certConf.command
	critOpt["source-address"] = certConf.srcAddr

	perms := ssh.Permissions{
		CriticalOptions: critOpt,
		Extensions:      certConf.extensions,
	}

	// Make a cert from our pubkey
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          1,
		CertType:        certConf.certType,
		KeyId:           certConf.keyId,
		ValidPrincipals: certConf.principals,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(certConf.duration).Unix()),
		Permissions:     perms,
	}

	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		err = fmt.Errorf("Failed to sign pubkey: %v", err)
		return nil, err
	}

	return cert, err
}
