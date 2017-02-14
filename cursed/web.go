package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

type httpParams struct {
	bastionIP   string
	bastionUser string
	cmd         string
	key         string
	remoteUser  string
	userIP      string
}

func webHandler(w http.ResponseWriter, r *http.Request, conf config) {
	// Do basic auth with the reverse proxy to prevent side-stepping it
	user, pass, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authorization Failure", http.StatusUnauthorized)
		return
	}
	if user != conf.ProxyUser || pass != conf.ProxyPass {
		log.Printf("Expected: %s:%s Received: %s:%s", conf.ProxyUser, conf.ProxyPass, user, pass)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Load our form parameters into a struct
	p := httpParams{
		bastionIP:   r.PostFormValue("bastionIP"),
		bastionUser: r.PostFormValue("bastionUser"),
		cmd:         r.PostFormValue("cmd"),
		key:         r.PostFormValue("key"),
		remoteUser:  r.PostFormValue("remoteUser"),
		userIP:      r.PostFormValue("userIP"),
	}

	// Make sure we have everything we need from our parameters
	err := validateHTTPParams(p, conf)
	if err != nil {
		errMsg := fmt.Sprintf("Param validation failure: %v", err)
		log.Printf(errMsg)
		http.Error(w, errMsg, http.StatusUnprocessableEntity)
		return
	}

	// Set our certificate validity times
	va := time.Now()
	vb := time.Now().Add(conf.dur)

	// Generate a fingerprint of the received public key for our key_id string
	fp := ""
	pk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(p.key))
	if err == nil {
		fp = ssh.FingerprintLegacyMD5(pk)
	}

	// Generate our key_id for the certificate
	//keyID := fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] ca[%s] valid to[%s]",
	keyID := fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] valid to[%s]",
		p.bastionUser, p.userIP, p.cmd, fp, vb.Format(time.RFC822))

	log.Printf("Signing request: |%s|", keyID)

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
	key, err := signPubKey(conf.caSigner, []byte(p.key), cc)
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	w.Write(ssh.MarshalAuthorizedKey(key))
}

func validateHTTPParams(p httpParams, conf config) error {
	if conf.ForceCmd && p.cmd == "" {
		err := fmt.Errorf("cmd missing from request")
		return err
	}

	if p.bastionIP == "" {
		err := fmt.Errorf("bastionIP missing from request")
		return err
	}
	if p.bastionUser == "" {
		err := fmt.Errorf("bastionUser missing from request")
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
	if p.userIP == "" {
		err := fmt.Errorf("userIP missing from request")
		return err
	}

	return nil
}
