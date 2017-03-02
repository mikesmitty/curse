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

func requestCert(conf *config, pubKey string) ([]byte, int, error) {
	var tlsConf *tls.Config

	// Prep our mutual auth cert/key and TLS settings
	if conf.MutualAuth {
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

		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{keyPair},
			RootCAs:      certPool,
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
	form.Add("bastionIP", conf.BastionIP)
	form.Add("cmd", conf.cmd)
	form.Add("key", pubKey)
	form.Add("remoteUser", conf.SSHUser)
	form.Add("userIP", conf.userIP)

	req, err := http.NewRequest("POST", conf.URL, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if !conf.MutualAuth {
		/* Using basic auth for the initial prototype, since presumably this SSL certificate will be valid and
		relatively insusceptible to MITM. Also, the digest auth client libraries I've seen are kinda bad.
		I plan to come back and try writing a digest library once I get the prototype functional (and not in
		a time crunch to make a demo). */
		// Looks like support for auth_digest is somewhat lacking in nginx. This will have to wait a while longer.
		// Maybe I'll add digest support for use with Apache at some point
		req.SetBasicAuth(conf.userName, conf.userPass)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 2, fmt.Errorf("Connection failed: %v\n", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 2, fmt.Errorf("Failed to process response: %v\n", err)
	}

	return respBody, resp.StatusCode, nil
}
