package jinxlib

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func requestSSHCert(conf *config, pubKey string) ([]byte, int, error) {
	// Prep our mutual auth cert/key and TLS settings
	keyPair, err := tls.LoadX509KeyPair(conf.SSLCertFile, conf.SSLKeyFile)
	if err != nil {
		return nil, 1, fmt.Errorf("Failed to load TLS mutual auth client certfificate/key pair: %v", err)
	}
	ca, err := ioutil.ReadFile(conf.SSLCAFile)
	if err != nil {
		return nil, 1, fmt.Errorf("Failed to load TLS mutual auth CA: %v", err)
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

	// Assemble our POST form values
	form := url.Values{}
	form.Add("bastionIP", conf.BastionIP)
	form.Add("cmd", conf.cmd)
	form.Add("key", pubKey)
	form.Add("remoteUser", conf.SSHUser)
	form.Add("userIP", conf.userIP)

	req, err := http.NewRequest("POST", conf.URLCurse, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 2, fmt.Errorf("Connection failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 2, fmt.Errorf("Failed to process response: %v", err)
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
			return nil, 1, fmt.Errorf("Failed to load TLS mutual auth CA: %v", err)
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(ca)

		tlsConf = &tls.Config{
			RootCAs: certPool,
		}
		tlsConf.BuildNameToCertificate()
	} else {
		// For regular TLS connections set our verify settings
		tlsConf = &tls.Config{InsecureSkipVerify: conf.Insecure}
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConf,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(conf.Timeout) * time.Second,
	}

	// Assemble our POST form values
	form := url.Values{}
	form.Add("csr", string(csrBytes))
	form.Add("userIP", conf.userIP)

	req, err := http.NewRequest("POST", conf.URLAuth, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	req.SetBasicAuth(conf.userName, conf.userPass)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 2, fmt.Errorf("Connection failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 2, fmt.Errorf("Failed to process response: %v", err)
	}

	return respBody, resp.StatusCode, nil
}
