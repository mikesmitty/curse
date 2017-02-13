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

func webHandler(w http.ResponseWriter, r *http.Request, caKey *ssh.Signer) {
	p := httpParams{
		bastionIP:   r.PostFormValue("bastionIP"),
		bastionUser: r.PostFormValue("bastionUser"),
		cmd:         r.PostFormValue("cmd"),
		key:         r.PostFormValue("key"),
		remoteUser:  r.PostFormValue("remoteUser"),
		userIP:      r.PostFormValue("userIP"),
	}

	err := validateHTTPParams(p)
	if err != nil {
		errMsg := fmt.Sprintf("Param validation failure: %v", err)
		log.Printf(errMsg)
		http.Error(w, errMsg, 422)
		return
	}

	va := time.Now()
	vb := time.Now().Add(duration)

	fp := ""
	pk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(p.key))
	if err == nil {
		fp = ssh.FingerprintLegacyMD5(pk)
	}

	//keyID := fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] ca[%s] valid to[%s]",
	keyID := fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] valid to[%s]",
		p.remoteUser, p.userIP, p.cmd, fp, vb.Format(time.RFC822))

	log.Printf("Signing request: |%s|", keyID)

	cc := certConfig{
		certType:    ssh.UserCert,
		command:     p.cmd,
		duration:    duration,
		extensions:  extensions,
		keyID:       keyID,
		principals:  []string{p.remoteUser},
		srcAddr:     p.bastionIP,
		validAfter:  va,
		validBefore: vb,
	}

	key, err := signPubKey(*caKey, []byte(p.key), cc)
	if err != nil {
		log.Printf("%v", err)
	} else {
		w.Write(ssh.MarshalAuthorizedKey(key))
	}

}

func validateHTTPParams(p httpParams) error {
	if forceCmd && p.cmd == "" {
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
