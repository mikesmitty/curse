package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/viper"
)

type config struct {
	certFile    string
	privKeyFile string
	pubKeyFile  string
	userIP      string

	AutoGenKeys   bool
	BastionIP     string
	Insecure      bool
	KeyGenBitSize int
	KeyGenPubKey  string
	KeyGenType    string
	PubKey        string
	SSHUser       string
	Timeout       int
	URL           string
}

func main() {
	// Process/load our config options
	conf, err := getConf()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Get our pubkey
	pubKey, err := getPubKey(conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
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

	// Send our pubkey to be signed
	respBody, statusCode, err := requestCert(conf, user, pass, string(pubKey))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch statusCode {
	case http.StatusOK:
		err = ioutil.WriteFile(conf.certFile, respBody, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write cert file: %v\n", err)
			os.Exit(1)
		}
	case http.StatusUnprocessableEntity:
		if conf.AutoGenKeys {
			fmt.Fprintln(os.Stderr, "Server denied pubkey due to age. Regenerating keypairs. Run command again after keys are regenerated.")
			err = saveNewKeyPair(conf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to generate key pair: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Server denied pubkey due to age and automatic regeneration disabled. Please manually regenerate your SSH keys.")
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, string(respBody))
		os.Exit(statusCode)
	}
}

func init() {
	viper.SetConfigName("jinx") // name of config file (without extension)
	viper.AddConfigPath("/etc/jinx")
	viper.AddConfigPath("$HOME/.jinx/")
	viper.ReadInConfig()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		//log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}

	viper.SetDefault("autogenkeys", true)
	viper.SetDefault("bastionip", "")
	viper.SetDefault("insecure", false)
	viper.SetDefault("keygenbitsize", 2048)
	viper.SetDefault("keygenpubkey", "$HOME/.ssh/id_jinx.pub")
	viper.SetDefault("keygentype", "ed25519")
	viper.SetDefault("pubkey", "$HOME/.ssh/id_ed25519.pub")
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
			return nil, fmt.Errorf("Could not find server's public IP. bastionip field required")
		}
	}
	if conf.PubKey == "" {
		return nil, fmt.Errorf("pubkey is a required configuration field")
	}

	// Replace $HOME with the current user's home directory
	conf.PubKey = expandHome(conf.PubKey)
	conf.KeyGenPubKey = expandHome(conf.KeyGenPubKey)

	// Generate our key and certificate filepaths
	r := regexp.MustCompile(`\.pub$`)
	if conf.AutoGenKeys {
		conf.certFile = r.ReplaceAllString(conf.KeyGenPubKey, "-cert.pub")
		conf.pubKeyFile = conf.KeyGenPubKey
	} else {
		conf.certFile = r.ReplaceAllString(conf.PubKey, "-cert.pub")
		conf.pubKeyFile = conf.PubKey
	}
	conf.privKeyFile = r.ReplaceAllString(conf.pubKeyFile, "")
	if conf.privKeyFile == conf.pubKeyFile {
		return nil, fmt.Errorf("Invalid public key name (must end in .pub): %s", conf.pubKeyFile)
	}

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
