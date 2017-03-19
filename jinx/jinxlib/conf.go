package jinxlib

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

type config struct {
	certFile    string
	cmd         string
	privKeyFile string
	pubKeyFile  string
	userIP      string
	userName    string
	userPass    string
	verbose     bool

	AutoGenKeys   bool
	BastionIP     string
	Insecure      bool
	KeyGenBitSize int
	KeyGenPubKey  string
	KeyGenType    string
	PubKey        string
	SSHUser       string
	SSLCAFile     string
	SSLCertFile   string
	SSLKeyCurve   string
	SSLKeyFile    string
	Timeout       int
	URLAuth       string
	URLCurse      string
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
	conf.SSLCAFile = expandHome(conf.SSLCAFile)
	conf.SSLCertFile = expandHome(conf.SSLCertFile)
	conf.SSLKeyFile = expandHome(conf.SSLKeyFile)

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
	if strings.HasPrefix(conf.URLAuth, "http://") {
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
	if conf.userIP == "" && len(scs) > 0 {
		conf.userIP = scs[0]
	}
	if conf.userIP == "" {
		conf.userIP = "IP missing"
	}

	return &conf, nil
}
