package jinxlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mikesmitty/edkey"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

func getPubKey(conf *config) ([]byte, error) {
	var (
		pubKey []byte
		err    error
	)

	// Check if our keys exist, otherwise generate it
	if conf.AutoGenKeys {
		if _, err := os.Stat(conf.privKeyFile); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Configured SSH private key missing (%s), generating new key pair.\n", conf.privKeyFile)
			err = saveNewKeyPair(conf)
			if err != nil {
				return nil, fmt.Errorf("Failed to generate key pair: %v", err)
			}
		}
		if _, err := os.Stat(conf.pubKeyFile); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Configured SSH public key missing (%s), generating new key pair.\n", conf.pubKeyFile)
			err = saveNewKeyPair(conf)
			if err != nil {
				return nil, fmt.Errorf("Failed to generate key pair: %v", err)
			}
		}
	}

	// Read in our specified pubkey file
	pubKey, err = ioutil.ReadFile(conf.pubKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read PubKey file: %v", err)
	}

	return pubKey, nil
}

func genKeyPair(conf *config) ([]byte, []byte, error) {
	var (
		authorizedKey []byte
		privateKeyPEM []byte
		err           error
	)

	switch conf.KeyGenType {
	case "ed25519":
		// Generate our private and public keys
		pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to generate ed25519 private key: %v", err)
		}
		publicKey, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to convert ed25519 pubkey format: %v", err)
		}

		// Convert to a writable format
		pemKey := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(privateKey),
		}
		privateKeyPEM = pem.EncodeToMemory(pemKey)
		authorizedKey = ssh.MarshalAuthorizedKey(publicKey)
	case "ecdsa":
		var privateKey *ecdsa.PrivateKey

		// Generate our private and public keys
		if conf.KeyGenBitSize == 256 {
			privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		} else if conf.KeyGenBitSize == 384 {
			privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		} else if conf.KeyGenBitSize == 521 {
			privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		} else {
			return nil, nil, fmt.Errorf("Invalid keygenbitsize for ecdsa: %d", conf.KeyGenBitSize)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to generate ecdsa private key: %v", err)
		}
		pubKey, ok := privateKey.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("ecdsa.PublicKey type assertion failed on an ecdsa public key. This should never ever happen.")
		}
		publicKey, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to convert ecdsa pubkey format: %v", err)
		}

		// Convert to a writable format
		ecBytes, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to convert ecdsa private key format: %v", err)
		}
		pemKey := &pem.Block{
			Type:  "EC PARAMETERS",
			Bytes: ecBytes,
		}
		privateKeyPEM = pem.EncodeToMemory(pemKey)
		authorizedKey = ssh.MarshalAuthorizedKey(publicKey)
	case "rsa":
		// Generate our private and public keys
		privateKey, err := rsa.GenerateKey(rand.Reader, conf.KeyGenBitSize)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to generate rsa private key: %v", err)
		}
		pubKey, ok := privateKey.Public().(*rsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("rsa.PublicKey type assertion failed on an rsa public key. This should never ever happen.")
		}
		publicKey, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to convert rsa pubkey format: %v", err)
		}

		// Convert to a writable format
		pemKey := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		privateKeyPEM = pem.EncodeToMemory(pemKey)
		authorizedKey = ssh.MarshalAuthorizedKey(publicKey)
	default:
		return nil, nil, fmt.Errorf("Key type '%s' not recognized. Unable to generate new keypair.", conf.KeyGenType)
	}

	return authorizedKey, privateKeyPEM, nil
}

func saveNewKeyPair(conf *config) error {
	if !conf.AutoGenKeys {
		return fmt.Errorf("autogenkeys disabled. Not generating new keys.")
	}

	publicKey, privateKey, err := genKeyPair(conf)
	if err != nil {
		return fmt.Errorf("Failed to generate new keys: %v\n", err)
	}

	err = ioutil.WriteFile(conf.privKeyFile, privateKey, 0600)
	if err != nil {
		return fmt.Errorf("Failed to write private key file: %v\n", err)
	}
	err = ioutil.WriteFile(conf.pubKeyFile, publicKey, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write public key file: %v\n", err)
	}

	return nil
}
