package jinxlib

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func requestCert(conf *config, user, pass, pubKey string) ([]byte, int, error) {
	/* Using basic auth for the initial prototype, since presumably this SSL certificate will be valid and
	relatively insusceptible to MITM. Also, the digest auth client libraries I've seen are kinda bad.
	I plan to come back and try writing a digest library once I get the prototype functional (and not in
	a time crunch to make a demo). */
	// Looks like support for auth_digest is somewhat lacking in nginx. This will have to wait a while longer.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: conf.Insecure},
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
	req.SetBasicAuth(user, pass)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("Connection failed: %v\n", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to process response: %v\n", err)
	}

	return respBody, resp.StatusCode, nil
}
