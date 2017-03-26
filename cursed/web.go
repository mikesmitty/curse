package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

type httpParams struct {
	bastionIP  string
	cmd        string
	key        string
	remoteUser string
	userIP     string
	user       string
}

func sshCertHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	// Load our form parameters into a struct
	p := httpParams{
		bastionIP:  r.PostFormValue("bastionIP"),
		cmd:        r.PostFormValue("cmd"),
		key:        r.PostFormValue("key"),
		remoteUser: r.PostFormValue("remoteUser"),
		userIP:     r.PostFormValue("userIP"),
	}

	// Set our certificate validity times
	va := time.Now().Add(-30 * time.Second)
	vb := time.Now().Add(conf.dur)

	// Generate a fingerprint of the received public key for our key_id string
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.key))
	if err != nil {
		log.Printf("Unable to parse authorized key |%s|", p.key)
		http.Error(w, "Unable to parse authorized key", http.StatusBadRequest)
		return
	}
	// Using md5 because that's what ssh-keygen prints out, making searches for a particular key easier
	fp := ssh.FingerprintLegacyMD5(pk)

	// Check for the client certificate
	if len(r.TLS.PeerCertificates) > 0 {
		p.user = r.TLS.PeerCertificates[0].Subject.CommonName
	} else {
		log.Printf("Invalid client certificate")
		http.Error(w, "Invalid client certificate", http.StatusBadRequest)
		return
	}

	// Generate our key_id for the certificate
	//keyID := fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] ca[%s] valid to[%s]",
	keyID := fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] valid to[%s]",
		p.user, p.userIP, p.cmd, fp, vb.Format(time.RFC3339))

	// Log the request
	log.Printf("SSH request: %s", keyID)

	// Check if user is authorized for this principal
	err = unixgroup(conf, p.user, p.remoteUser)
	if err != nil {
		log.Printf("Authorization failure: %v", err)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	// Make sure we have everything we need from our parameters
	err = validateHTTPParams(conf, p)
	if err != nil {
		errMsg := fmt.Sprintf("validation failure: %v", err)
		log.Printf(errMsg)
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	// Check if we've seen this pubkey before and if it's too old
	expired, err := checkPubKeyAge(conf, fp)
	if expired {
		http.Error(w, "Submitted pubkey is too old. Please generate new key.", http.StatusUnprocessableEntity)
		return
	}

	// Set all of our certificate options
	cc := certConfig{
		certType:    ssh.UserCert,
		command:     p.cmd,
		extensions:  conf.exts,
		keyID:       keyID,
		principals:  []string{p.remoteUser},
		srcAddr:     p.bastionIP,
		validAfter:  va,
		validBefore: vb,
	}

	// Sign the public key
	authorizedKey, err := signPubKey(conf.sshCASigner, []byte(p.key), cc)
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Write(authorizedKey)
}

func validateHTTPParams(conf *config, p httpParams) error {
	if conf.ForceCmd && p.cmd == "" {
		err := fmt.Errorf("cmd missing from request")
		return err
	}
	if p.bastionIP == "" || !validIP(p.bastionIP) {
		err := fmt.Errorf("bastionIP is invalid")
		return err
	}
	if p.key == "" {
		err := fmt.Errorf("key missing from request")
		return err
	}
	if p.remoteUser == "" {
		err := fmt.Errorf("remoteUser missing from request")
		return err
	}
	if conf.RequireClientIP && !validIP(p.userIP) {
		err := fmt.Errorf("invalid userIP")
		log.Printf("invalid userIP: |%s|", p.userIP) // FIXME This should be re-evaluated in the logging refactor
		return err
	}
	if p.user == "" {
		err := fmt.Errorf("empty username not permitted")
		return err
	}

	return nil
}
