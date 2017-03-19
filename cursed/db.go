package main

import (
	"fmt"
	"math/big"

	"github.com/boltdb/bolt"
)

func getDBSerial(conf *config) (*big.Int, error) {
	var serial *big.Int
	key := []byte("serial")

	err := conf.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(conf.bucketNameSerial)
		if bucket == nil {
			return fmt.Errorf("WARNING: Did not find DB bucket %q. This should only happen with a new db file", conf.bucketNameSerial)
		}

		// Get serial from database and convert to int
		val := bucket.Get(key)
		serial = big.NewInt(0)
		serial = serial.SetBytes(val)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return serial, nil
}

func incDBSerial(conf *config) (*big.Int, error) {
	var newSerial *big.Int
	key := []byte("serial")

	err := conf.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(conf.bucketNameSerial)
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
		return nil, fmt.Errorf("Failed to increment certificate serial counter in database: %v", err)
	}

	return newSerial, nil
}

func setDBSerial(conf *config, serial *big.Int) error {
	key := []byte("serial")

	err := conf.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(conf.bucketNameSerial)
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
		return fmt.Errorf("Failed to update certificate serial counter in database: %v", err)
	}

	return nil
}
