package jinxlib

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os/user"
	"time"
)

type params struct {
	BastionIP   string `json:"bastion_ip,omitempty"`
	BastionUser string `json:"bastion_user,omitempty"`
	Cmd         string `json:"cmd,omitempty"`
	CSR         string `json:"csr,omitempty"`
	Key         string `json:"key,omitempty"`
	RemoteUser  string `json:"remote_user,omitempty"`
	UserIP      string `json:"user_ip,omitempty"`
}

func requestSSHCert(conf *config, pubKey string) ([]byte, int, error) {
	// Prep our mutual auth cert/key and TLS settings
	keyPair, err := tls.LoadX509KeyPair(conf.SSLCertFile, conf.SSLKeyFile)
	if err != nil {
		return nil, 1, fmt.Errorf("failed to load tls mutual auth client certfificate/key pair: %v", err)
	}
	ca, err := ioutil.ReadFile(conf.SSLCAFile)
	if err != nil {
		return nil, 1, fmt.Errorf("failed to load tls mutual auth ca: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		RootCAs:      certPool,
	}
	tlsConf.BuildNameToCertificate()

	tr := &http.Transport{
		TLSClientConfig: tlsConf,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(conf.Timeout) * time.Second,
	}

	// Assemble our parameters
	p := params{
		BastionIP:  conf.BastionIP,
		Cmd:        conf.cmd,
		Key:        pubKey,
		RemoteUser: conf.SSHUser,
		UserIP:     conf.userIP,
	}

	// Assemble our json payload
	pl, err := json.Marshal(p)
	if err != nil {
		return nil, 1, fmt.Errorf("failed to marshal json for request: %v", err)
	}

	req, err := http.NewRequest("POST", conf.URLCurse, bytes.NewBuffer(pl))
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 2, fmt.Errorf("connection failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 2, fmt.Errorf("failed to process response: %v", err)
	}

	return respBody, resp.StatusCode, nil
}

func requestTLSCert(conf *config) ([]byte, int, error) {
	var csrBytes []byte

	// Generate CSR since our cert is invalid
	csrBytes, err := genTLSCSR(conf)
	if err != nil {
		return nil, 1, err
	}

	var tlsConf *tls.Config
	if conf.UseSSLCA {
		// Use /etc/jinx/ca.crt as our CA for verifying the curse daemon
		ca, err := ioutil.ReadFile(conf.SSLCAFile)
		if err != nil {
			return nil, 1, fmt.Errorf("failed to load tls mutual auth ca: %v", err)
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(ca)

		tlsConf = &tls.Config{
			RootCAs: certPool,
		}
		tlsConf.BuildNameToCertificate()
	} else {
		// For regular tls connections set our verify settings
		tlsConf = &tls.Config{InsecureSkipVerify: conf.Insecure}
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConf,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(conf.Timeout) * time.Second,
	}

	// Get our system username
	u, err := user.Current()
	if err != nil {
		return nil, 1, fmt.Errorf("failed to get username: %v", err)
	}
	curUser := u.Username

	// Assemble our parameters
	p := params{
		BastionUser: curUser,
		CSR:         string(csrBytes),
		UserIP:      conf.userIP,
	}

	// Assemble our json payload
	pl, err := json.Marshal(p)
	if err != nil {
		return nil, 1, fmt.Errorf("failed to marshal json for request: %v", err)
	}

	req, err := http.NewRequest("POST", conf.URLAuth, bytes.NewBuffer(pl))
	req.Header.Add("Content-Type", "application/json")

	req.SetBasicAuth(conf.userName, conf.userPass)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 2, fmt.Errorf("connection failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 2, fmt.Errorf("failed to process response: %v", err)
	}

	return respBody, resp.StatusCode, nil
}
