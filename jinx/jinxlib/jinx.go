package jinxlib

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/bgentry/speakeasy"
)

func Jinx(args []string) {
	// Process/load our config options
	conf, err := getConf()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Use our first argument as our command
	if len(args) > 0 {
		conf.cmd = args[0]
	}

	// Get our pubkey
	pubKey, err := getPubKey(conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Disable password prompt when using TLS mutual auth
	// Also disabling insecure nag-mode since the CA may not necessarily be trusted by the system
	if !conf.MutualAuth {
		// Nag-mode for inadvertent/malicious insecure setting
		if conf.Insecure {
			fmt.Println("Warning, your password is about to be sent insecurely. ctrl+c to quit")
		}

		// Read in our username and password
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Username: ")
		user, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Input error: %v\n", err)
			os.Exit(1)
		}
		conf.userName = strings.TrimSpace(user)

		conf.userPass, err = speakeasy.Ask("Password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Shell error: %v\n", err)
			os.Exit(1)
		}
	}

	// Send our pubkey to be signed
	respBody, statusCode, err := requestCert(conf, string(pubKey))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(statusCode)
	}

	switch statusCode {
	case http.StatusOK:
		err = ioutil.WriteFile(conf.certFile, respBody, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write cert file: %v\n", err)
			os.Exit(1)
		}
	case http.StatusUnprocessableEntity:
		if conf.AutoGenKeys {
			fmt.Fprintln(os.Stderr, "Server denied pubkey due to age. Regenerating keypairs. Run command again after keys are regenerated.")
			err = saveNewKeyPair(conf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to generate key pair: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Server denied pubkey due to age and automatic regeneration disabled. Please manually regenerate your SSH keys.")
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, string(respBody))
		os.Exit(statusCode)
	}
}
