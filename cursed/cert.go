package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"time"

	"github.com/boltdb/bolt"

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
	var keyBirthday int64

	// Check if this fingerprint exists in our DB
	err := conf.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(conf.bucketName)
		if bucket == nil {
			msg := "WARNING: Did not find DB bucket %q. This should only happen with a new db file"
			return fmt.Errorf(msg, conf.bucketName)
		}

		// Get timestamp string from database and convert to int
		val := bucket.Get([]byte(fp))
		// Convert byte array to string to int64 (gross, I know)
		kb, err := strconv.ParseInt(string(val), 10, 64)
		if err != nil {
			msg := "ERROR: Timestamp in db corrupted for key %s: %v"
			return fmt.Errorf(msg, fp, err)
		}
		keyBirthday = int64(kb)

		return nil
	})
	if err != nil {
		log.Printf("%v", err)
		err = nil
	}

	// If this is a new key, add it to the database with a timestamp
	if keyBirthday == 0 {
		err = conf.db.Update(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(conf.bucketName)
			if err != nil {
				return err
			}

			// Convert unix timestamp to string to byte array and store in the DB (gross, I know)
			now := strconv.FormatInt(time.Now().Unix(), 10)
			err = bucket.Put([]byte(fp), []byte(now))
			if err != nil {
				return err
			}
			return nil
		})
	} else if keyBirthday > 0 {
		kb := time.Unix(keyBirthday, 0)
		keyAge := time.Now().Sub(kb)
		if keyAge > conf.keyLifeSpan {
			return true, nil
		}
	} else {
		err = fmt.Errorf("Something went very wrong. Negative timestamp encountered: %d", keyBirthday)
		return true, err
	}

	return false, nil
}

func loadCAKey(keyFile string) (ssh.Signer, error) {
	// Read in our private key PEM file
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		err = fmt.Errorf("Failed to read CA key file: '%v'", err)
		return nil, err
	}

	sk, err := ssh.ParsePrivateKey(key)
	if err != nil {
		err = fmt.Errorf("Failed to parse CA key: '%v'", err)
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
		Serial:          0,
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
