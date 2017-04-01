package main

import (
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
)

func dbAddPubKeyBday(conf *config, fp string) error {
	err := conf.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(conf.bucketNameFP)
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

	return err
}

func dbGetPubKeyAge(conf *config, fp string) (int64, bool, error) {
	var (
		keyBirthday int64
		ok          bool
	)

	// Check if this fingerprint exists in our DB
	err := conf.db.View(func(tx *bolt.Tx) error {
		var err error

		bucket := tx.Bucket(conf.bucketNameFP)
		if bucket == nil {
			msg := "did not find db bucket %q"
			ok = false
			return fmt.Errorf(msg, conf.bucketNameFP)
		}

		// Get timestamp string from database and convert to int
		val := bucket.Get([]byte(fp))
		if len(val) == 0 {
			keyBirthday = 0
			ok = true
			return nil
		}

		// Convert byte array to string to int64
		keyBirthday, err = strconv.ParseInt(string(val), 10, 64)
		if err != nil {
			msg := "timestamp in db corrupted for key %s: %v"
			ok = false
			return fmt.Errorf(msg, fp, err)
		}

		ok = true
		return nil
	})

	return keyBirthday, ok, err
}

func dbInitPubKeyBucket(conf *config) error {
	err := conf.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(conf.bucketNameFP)

		return err
	})

	return err
}

func dbIncSSHSerial(conf *config) (uint64, error) {
	var newSerial uint64
	key := conf.sshCAFP

	err := conf.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(conf.bucketNameSSHSerial)
		if err != nil {
			return err
		}

		// Get serial from database and convert to uint64
		var serial uint64
		val := bucket.Get(key)
		if len(val) == 0 {
			serial = 0
		} else {
			serial, err = strconv.ParseUint(string(val), 10, 64)
			if err != nil {
				return fmt.Errorf("ssh serial counter in db corrupted: %v", err)
			}
		}

		// Increment and update the serial
		newSerial = serial + 1
		sb := strconv.FormatUint(newSerial, 10)
		err = bucket.Put(key, []byte(sb))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to increment ssh certificate serial counter in database: %v", err)
	}

	return newSerial, nil
}

func dbSetSSHSerial(conf *config, serial uint64) error {
	key := conf.sshCAFP

	err := conf.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(conf.bucketNameSSHSerial)
		if err != nil {
			return err
		}

		// Save the serial number counter to the db
		serial := strconv.FormatUint(serial, 10)
		err = bucket.Put(key, []byte(serial))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update ssh certificate serial counter in database: %v", err)
	}

	return nil
}

func dbIncTLSSerial(conf *config) (*big.Int, error) {
	var newSerial *big.Int
	key := []byte("serial")

	err := conf.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(conf.bucketNameTLSSerial)
		if err != nil {
			return err
		}

		// Get serial from database and convert to uint64
		val := bucket.Get(key)
		serial := big.NewInt(0)
		serial = serial.SetBytes(val)

		// Increment and update the serial
		plusOne := big.NewInt(1)
		newSerial = serial.Add(serial, plusOne)
		err = bucket.Put(key, newSerial.Bytes())
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to increment tls certificate serial counter in database: %v", err)
	}

	return newSerial, nil
}

func dbSetTLSSerial(conf *config, serial *big.Int) error {
	key := []byte("serial")

	err := conf.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(conf.bucketNameTLSSerial)
		if err != nil {
			return err
		}

		err = bucket.Put(key, serial.Bytes())
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update tls certificate serial counter in database: %v", err)
	}

	return nil
}
