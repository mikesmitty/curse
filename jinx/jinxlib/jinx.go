package jinxlib

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Jinx Run the jinx client to generate keys and make request
func Jinx(verbose bool, args []string) {
	// Process/load our config options
	conf, err := getConf()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	conf.verbose = verbose

	// Use our first argument as our command
	if len(args) > 0 {
		conf.cmd = strings.Join(args, " ")
	}

	// Get our pubkey
	pubKey, err := getPubKey(conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Check if our TLS key/cert exist and are valid
	ok, keyExists, err := checkTLSCert(conf)
	if !ok {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if ok && !keyExists {
		// Key is invalid or does not yet exist
		keyBytes, err := genTLSKey(conf)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		err = saveTLSKey(conf, keyBytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if ok && err != nil {
		// Cert is invalid, need to request a new cert
		if verbose {
			fmt.Fprintln(os.Stderr, err)
		}

		// Prompt user for username and password
		conf.userName, conf.userPass, err = getUserPass(conf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}

		// Make the cert request
		if conf.verbose {
			fmt.Fprintln(os.Stderr, "making tls cert request")
		}
		respBody, statusCode, err := requestTLSCert(conf)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(statusCode)
		}

		switch statusCode {
		case http.StatusOK:
			err = ioutil.WriteFile(conf.SSLCertFile, respBody, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to write tls cert file: %v\n", err)
				os.Exit(1)
			}
		default:
			out := fmt.Sprintf("server response: %s", respBody)
			fmt.Fprintf(os.Stderr, out)
			os.Exit(statusCode)
		}
	}

	// Send our pubkey to be signed
	if conf.verbose {
		fmt.Fprintln(os.Stderr, "making ssh cert request")
	}
	respBody, statusCode, err := requestSSHCert(conf, string(pubKey))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(statusCode)
	}

	switch statusCode {
	case http.StatusOK:
		err = ioutil.WriteFile(conf.certFile, respBody, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write cert file: %v\n", err)
			os.Exit(1)
		}
	case http.StatusUnprocessableEntity:
		if conf.AutoGenKeys {
			fmt.Fprintln(os.Stderr, "server denied pubkey due to age. regenerating keypairs. run command again after keys are regenerated.")
			err = saveNewKeyPair(conf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to generate key pair: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "server denied pubkey due to age and automatic regeneration disabled. please manually regenerate your ssh keys.")
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, string(respBody))
		os.Exit(statusCode)
	}
}
