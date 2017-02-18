package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/viper"
)

type config struct {
	certFile string
	userIP   string

	BastionIP string
	Insecure  bool
	PubKey    string
	SSHUser   string
	Timeout   int
	URL       string
}

func main() {
	// Process/load our config options
	conf, err := getConf()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Read in our pubkey file
	pubKey, err := ioutil.ReadFile(conf.PubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read PubKey file: %v\n", err)
		os.Exit(1)
	}

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
	user = strings.TrimSpace(user)

	pass, err := speakeasy.Ask("Password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Shell error: %v\n", err)
		os.Exit(1)
	}

	/* Using basic auth for the initial prototype, since presumably this SSL certificate will be valid and
	relatively insusceptible to MITM. Also, the digest auth client libraries I've seen are kinda bad.
	I plan to come back and try writing a digest library once I get the prototype functional (and not in
	a time crunch to make a demo). */
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
	form.Add("key", string(pubKey))
	form.Add("remoteUser", conf.SSHUser)
	form.Add("userIP", conf.userIP)

	req, err := http.NewRequest("POST", conf.URL, strings.NewReader(form.Encode()))
	req.SetBasicAuth(user, pass)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to process response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode == 200 {
		err = ioutil.WriteFile(conf.certFile, respBody, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write cert file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, string(respBody))
		os.Exit(resp.StatusCode)
	}
}

func init() {
	viper.SetConfigName(".jinx")     // name of config file (without extension)
	viper.AddConfigPath("/etc/jinx") // /etc/jinx/.jinx.{yaml,toml,json} makes little sense. FIXME
	viper.AddConfigPath("$HOME")
	viper.ReadInConfig()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		//log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}

	viper.SetDefault("bastionip", "")
	viper.SetDefault("insecure", false)
	viper.SetDefault("pubkey", "")      // FIXME Need to revisit this
	viper.SetDefault("sshuser", "root") // FIXME Need to revisit this?
	viper.SetDefault("timeout", 30)
	viper.SetDefault("url", "https://localhost/")
}

func getConf() (*config, error) {
	// Read config into a struct
	var conf config
	err := viper.Unmarshal(&conf)
	if err != nil {
		return nil, fmt.Errorf("Unable to process config: %v", err)
	}

	// Verify config options
	if conf.BastionIP == "" {
		conf.BastionIP, _ = getBastionIP()
		if conf.BastionIP == "" {
			return nil, fmt.Errorf("could not find server's public IP. bastionip field required")
		}
	}
	if conf.PubKey == "" {
		return nil, fmt.Errorf("pubkey is a required configuration field")
	}

	conf.certFile = strings.Replace(conf.PubKey, ".pub", "-cert.pub", 1)

	// Check for non-SSL URL configuration (for warning)
	if strings.HasPrefix(conf.URL, "http://") {
		conf.Insecure = true
	}

	// Try to get the user's local IP from env variables
	sc := os.Getenv("SSH_CLIENT")
	scs := strings.Split(sc, " ")
	if len(scs) > 0 {
		conf.userIP = scs[0]
	}
	sc = os.Getenv("SSH_CONNECTION")
	scs = strings.Split(sc, " ")
	if conf.userIP == "" && len(scs) != 0 {
		conf.userIP = scs[0]
	}
	if conf.userIP == "" {
		conf.userIP = "IP missing"
	}

	return &conf, nil
}
