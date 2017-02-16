package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/viper"
)

type config struct {
	BastionIP string
	CertFile  string
	PubKey    string
	SSHUser   string
	Timeout   int
	URL       string
	UserIP    string
}

func main() {
	// Read config into a struct
	var conf config
	err := viper.Unmarshal(&conf)
	if err != nil {
		log.Fatalf("Unable to read config into struct: %v", err)
	}
	// Verify config options
	// FIXME Need to revisit this
	if conf.BastionIP == "" {
		log.Fatalf("bastionip is a required configuration field")
	}
	if conf.PubKey == "" {
		log.Fatalf("pubkey is a required configuration field")
	}
	// FIXME Need to revisit this
	if conf.UserIP == "" {
		log.Fatalf("userip is a required configuration field")
	}

	// Read in our pubkey file
	pubKey, err := ioutil.ReadFile(conf.PubKey)
	if err != nil {
		log.Fatalf("Failed to read PubKey file: %v", err)
	}

	// Read in our username and password
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Username: ")
	user, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Input error: %v", err)
	}
	user = strings.TrimSpace(user)

	pass, err := speakeasy.Ask("Password: ")
	if err != nil {
		log.Fatalf("Shell error: %v", err)
	}

	/* Using basic auth for the initial prototype, since presumably this SSL certificate will be valid and
	relatively insusceptible to MITM. Also, the digest auth client libraries I've seen are kinda bad.
	I plan to come back and try writing a digest library once I get the prototype functional (and not in
	a time crunch to make a demo). */
	client := &http.Client{
		Timeout: time.Duration(conf.Timeout) * time.Second,
	}

	// Assemble our POST form values
	form := url.Values{}
	form.Add("bastionIP", conf.BastionIP)
	form.Add("key", string(pubKey))
	form.Add("remoteUser", conf.SSHUser)
	form.Add("userIP", conf.UserIP)

	req, err := http.NewRequest("POST", conf.URL, strings.NewReader(form.Encode()))
	req.SetBasicAuth(user, pass)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to process response: %v", err)
	}

	//fmt.Println(string(respBody))

	err = ioutil.WriteFile(conf.CertFile, respBody, 0644)
	if err != nil {
		log.Fatal("Failed to write cert file: %v", err)
	}
}

func init() {
	viper.SetConfigName(".jinx") // name of config file (without extension)
	viper.AddConfigPath("/etc/jinx")
	viper.AddConfigPath("$HOME")
	viper.ReadInConfig()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}

	viper.SetDefault("bastionip", "")   // FIXME Need to revisit this
	viper.SetDefault("certfile", "")    // FIXME Need to revisit this
	viper.SetDefault("pubkey", "")      // FIXME Need to revisit this
	viper.SetDefault("sshuser", "root") // FIXME Need to revisit this
	viper.SetDefault("timeout", 30)
	viper.SetDefault("url", "https://127.0.0.1/")
	viper.SetDefault("userip", "1.1.1.1") // FIXME Need to revisit this
}
