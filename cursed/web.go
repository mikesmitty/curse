package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type httpParams struct {
	BastionIP   string `json:"bastion_ip,omitempty"`
	BastionUser string `json:"bastion_user,omitempty"`
	Cmd         string `json:"cmd,omitempty"`
	CSR         string `json:"csr,omitempty"`
	Key         string `json:"key,omitempty"`
	RemoteUser  string `json:"remote_user,omitempty"`
	UserIP      string `json:"user_ip,omitempty"`

	user string
}

func getJSONParams(r *http.Request) (httpParams, error) {
	var p httpParams

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return p, err
	}
	r.Body.Close()

	err = json.Unmarshal(body, &p)
	if err != nil {
		return p, err
	}

	return p, nil
}

func sshCertHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	// Set up some useful info for logging
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) == 0 {
		log.Print("critical error, could not get client IP from request")
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}
	ip := parts[0]
	un := "-"

	// Start up our logger
	logger := newLog(conf, ip, "ssh", "")

	// Load our form parameters into a struct
	p, err := getJSONParams(r)
	if err != nil {
		msg := fmt.Sprintf("bad json in request: %v", err)
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, "bad request", code)
		return
	}

	// Update our logger
	logger.rip = p.UserIP

	// Verify the client certificate
	if len(r.TLS.VerifiedChains) == 0 {
		msg := "no valid client certificate provided"
		code := http.StatusUnauthorized
		logger.req(un, code, msg)
		http.Error(w, "not authorized", code)
		return
	}

	// Get the client certificate CN
	p.user = r.TLS.PeerCertificates[0].Subject.CommonName
	un = p.user

	// Make sure we have everything we need from our parameters
	err = validateHTTPParams(conf, p)
	if err != nil {
		msg := fmt.Sprintf("validation failure: %v", err)
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, msg, code)
		return
	}

	// Set our certificate validity times
	va := time.Now().Add(-30 * time.Second)
	vb := time.Now().Add(conf.dur)

	// Generate a fingerprint of the received public key for our key_id string
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.Key))
	if err != nil {
		msg := "unable to parse authorized key"
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, msg, code)
		return
	}
	// Using md5 because that's what ssh-keygen prints out, making searches for a particular key easier
	fp := ssh.FingerprintLegacyMD5(pk)

	// Generate our key_id for the certificate
	keyID := fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] ca[%s] valid to[%s]",
		p.user, p.UserIP, p.Cmd, fp, conf.sshCAFP, vb.Format(time.RFC3339))

	// Check if user is authorized for this principal
	err = unixgroup(conf, p.user, p.RemoteUser)
	if err != nil {
		msg := fmt.Sprintf("authorization failure: %v", err)
		code := http.StatusUnauthorized
		logger.req(un, code, msg)
		http.Error(w, "not authorized", code)
		return
	}

	// Check if we've seen this pubkey before and if it's too old
	expired, err := checkPubKeyAge(conf, fp)
	if expired {
		code := http.StatusUnprocessableEntity
		msg := fmt.Sprintf("pubkey expired: user[%s] pubkey[%s]: %v", p.user, fp, err)
		logger.req(un, code, msg)
		http.Error(w, "submitted pubkey is too old. Please generate new key.", code)
		return
	}

	// Set all of our certificate options
	cc := certConfig{
		certType:    ssh.UserCert,
		command:     p.Cmd,
		extensions:  conf.exts,
		keyID:       keyID,
		principals:  []string{p.RemoteUser},
		srcAddr:     p.BastionIP,
		validAfter:  va,
		validBefore: vb,
	}

	// Sign the public key
	authorizedKey, err := signPubKey(conf, []byte(p.Key), cc)
	if err != nil {
		code := http.StatusInternalServerError
		msg := err.Error()
		logger.req(un, code, msg)
		http.Error(w, "server error", code)
		return
	}

	// Log the request
	code := http.StatusOK
	logger.req(un, code, keyID)

	// Return the cert
	w.Write(authorizedKey)
}

func validateHTTPParams(conf *config, p httpParams) error {
	if conf.ForceCmd && p.Cmd == "" {
		err := fmt.Errorf("cmd missing from request")
		return err
	}
	if p.BastionIP == "" || !validIP(p.BastionIP) {
		err := fmt.Errorf("bastionIP is invalid")
		return err
	}
	if p.Key == "" {
		err := fmt.Errorf("key missing from request")
		return err
	}
	if p.RemoteUser == "" {
		err := fmt.Errorf("remoteUser missing from request")
		return err
	}
	if conf.RequireClientIP && !validIP(p.UserIP) {
		err := fmt.Errorf("invalid userIP")
		log.Printf("invalid userIP: |%s|", p.UserIP) // FIXME This should be re-evaluated in the logging refactor
		return err
	}
	if p.user == "" {
		err := fmt.Errorf("empty username not permitted")
		return err
	}

	return nil
}
