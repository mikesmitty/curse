package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/boltdb/bolt"
	"github.com/spf13/viper"
)

type config struct {
	bucketName  []byte
	caSigner    ssh.Signer
	db          *bolt.DB
	dur         time.Duration
	exts        map[string]string
	keyLifeSpan time.Duration

	Addr       string
	CAKeyFile  string
	DBFile     string
	Duration   int
	Extensions []string
	ForceCmd   bool
	MaxKeyAge  int
	Port       int
	ProxyUser  string
	ProxyPass  string
	SSLKey     string
	SSLCert    string
}

func main() {
	// Read config into a struct
	var conf config
	err := viper.Unmarshal(&conf)
	if err != nil {
		log.Fatalf("Unable to read config into struct: %v", err)
	}
	// Hardcoding the DB bucket name
	conf.bucketName = []byte("pubkeybirthdays")

	// Require proxy authentication and SSL for security
	if conf.ProxyUser == "" || conf.ProxyPass == "" {
		log.Fatalf("proxyuser and proxypass are required fields")
	}
	if conf.SSLKey == "" || conf.SSLCert == "" {
		log.Fatalf("sslkey and sslcert are required fields")
	}

	// Check our certificate extensions (permissions) for validity
	var errSlice []error
	conf.exts, errSlice = validateExtensions(conf.Extensions)
	if len(errSlice) > 0 {
		for _, err := range errSlice {
			log.Printf("%v", err)
		}
	}

	// Convert our cert validity duration and pubkey lifespan from int to time.Duration
	conf.dur = time.Duration(conf.Duration) * time.Second
	conf.keyLifeSpan = time.Duration(conf.MaxKeyAge) * 24 * time.Hour

	// Load the CA key into an ssh.Signer
	conf.caSigner, err = loadCAKey(conf.CAKeyFile)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Open our key tracking database file
	conf.db, err = bolt.Open(conf.DBFile, 0600, nil)
	if err != nil {
		log.Fatalf("Could not open database file %v", err)
	}
	defer conf.db.Close()

	// Set our web handler function
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		webHandler(w, r, conf)
	})

	// Start our listener service
	addrPort := fmt.Sprintf("%s:%d", conf.Addr, conf.Port)
	log.Printf("Starting HTTPS server on %s", addrPort)
	err = http.ListenAndServeTLS(addrPort, conf.SSLCert, conf.SSLKey, nil)
	if err != nil {
		log.Fatalf("Listener service: %v", err)
	}
}

func init() {
	//if cfgFile != "" { // enable ability to specify config file via flag
	//	viper.SetConfigFile(cfgFile)
	//}

	viper.SetConfigName("cursed") // name of config file (without extension)
	viper.AddConfigPath("/etc/cursed")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME")
	viper.ReadInConfig()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}

	viper.SetDefault("addr", "127.0.0.1")
	viper.SetDefault("cakeyfile", "test_keys/user_ca")
	viper.SetDefault("dbfile", "./cursed.db")
	viper.SetDefault("duration", 2*60)
	viper.SetDefault("extensions", []string{"permit-pty"})
	viper.SetDefault("forcecmd", false)
	viper.SetDefault("maxkeyage", 90)
	viper.SetDefault("port", 8000)
	viper.SetDefault("proxyuser", "")
	viper.SetDefault("proxypass", "")
	viper.SetDefault("sslkey", "")
	viper.SetDefault("sslcert", "")
}

func validateExtensions(confExts []string) (map[string]string, []error) {
	validExts := []string{"permit-X11-forwarding", "permit-agent-forwarding",
		"permit-port-forwarding", "permit-pty", "permit-user-rc"}
	exts := make(map[string]string)
	errSlice := make([]error, 0)

	// Compare each of the config items from our config file against our known-good list, and
	// add them as a key in a map[string]string with empty value, as SSH expects
	for i := range confExts {
		valid := false
		for j := range validExts {
			if confExts[i] == validExts[j] {
				name := confExts[i]
				exts[name] = ""
				valid = true
				break
			}
		}
		if !valid {
			err := fmt.Errorf("Invalid extension in config: %s", confExts[i])
			errSlice = append(errSlice, err)
		}
	}

	return exts, errSlice
}
