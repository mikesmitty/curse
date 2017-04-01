package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"golang.org/x/crypto/ssh"
)

type certConfig struct {
	certType    uint32
	command     string
	extensions  map[string]string
	keyID       string
	principals  []string
	srcAddr     string
	validAfter  time.Time
	validBefore time.Time
}

func checkPubKeyAge(conf *config, fp string) (bool, error) {

	// Check our key's age from the DB
	keyBirthday, ok, err := dbGetPubKeyAge(conf, fp)
	if !ok && conf.KeyAgeCritical {
		return true, fmt.Errorf("critical - failed to verify pubkey age: [%s] %v", fp, err)
	} else if !ok {
		log.Printf("warning - failed to verify pubkey age: [%s] %v", fp, err)
	}

	// If this is a new key, add it to the database with a timestamp
	if keyBirthday == 0 {
		err = dbAddPubKeyBday(conf, fp)
		if err != nil {
			return true, err
		}
	} else if keyBirthday > 0 {
		kb := time.Unix(keyBirthday, 0)
		keyAge := time.Since(kb)
		if keyAge > conf.keyLifeSpan {
			return true, nil
		}
	} else {
		err = fmt.Errorf("Something went very wrong. Negative timestamp encountered: %d", keyBirthday)
		return true, err
	}

	return false, nil
}

func loadSSHCA(conf *config) (ssh.Signer, []byte, error) {
	// Read in our private key PEM file
	key, err := ioutil.ReadFile(conf.CAKeyFile)
	if err != nil {
		err = fmt.Errorf("Failed to read CA key file: '%v'", err)
		return nil, nil, err
	}

	sk, err := ssh.ParsePrivateKey(key)
	if err != nil {
		err = fmt.Errorf("Failed to parse CA key: '%v'", err)
		return nil, nil, err
	}

	// Get our CA fingerprint
	rawPub, err := ioutil.ReadFile(fmt.Sprintf("%s.pub", conf.CAKeyFile))
	if err != nil {
		err = fmt.Errorf("Failed to read CA pubkey file: '%v'", err)
		return nil, nil, err
	}

	// Parse the pubkey
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(rawPub)
	if err != nil {
		err = fmt.Errorf("Failed to parse CA pubkey: %v", err)
		return nil, nil, err
	}

	// Get the key's fingerprint for logging
	fp := ssh.FingerprintSHA256(pubKey)

	return sk, []byte(fp), nil
}

func signPubKey(conf *config, rawKey []byte, cc certConfig) ([]byte, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(rawKey) // FIXME look into handling additional fields
	if err != nil {
		return nil, fmt.Errorf("Failed to parse pubkey: %v", err)
	}

	// Get/update our ssh cert serial number
	serial, err := dbIncSSHSerial(conf)
	if err != nil {
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
		Serial:          serial,
		CertType:        cc.certType,
		KeyId:           cc.keyID,
		ValidPrincipals: cc.principals,
		ValidAfter:      uint64(cc.validAfter.Unix()),
		ValidBefore:     uint64(cc.validBefore.Unix()),
		Permissions:     perms,
	}

	err = cert.SignCert(rand.Reader, conf.sshCASigner)
	if err != nil {
		err = fmt.Errorf("Failed to sign pubkey: %v", err)
		return nil, err
	}
	authorizedKey := ssh.MarshalAuthorizedKey(cert)

	return authorizedKey, err
}
