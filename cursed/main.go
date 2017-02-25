package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
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
	userRegex   *regexp.Regexp

	Addr            string
	CAKeyFile       string
	DBFile          string
	Duration        int
	Extensions      []string
	ForceCmd        bool
	MaxKeyAge       int
	Port            int
	RequireClientIP bool
	SSLCA           string
	SSLCert         string
	SSLKey          string
	UserHeader      string
}

func main() {
	// Process/load our config options
	conf, err := getConf()
	if err != nil {
		log.Fatal(err)
	}

	// Convert our cert validity duration and pubkey lifespan from int to time.Duration
	conf.dur = time.Duration(conf.Duration) * time.Second
	if conf.MaxKeyAge < 0 {
		// Negative MaxKeyAge means unlimited age keys, set lifespan to 100 years
		conf.keyLifeSpan = 100 * 365 * 24 * time.Hour
	} else {
		conf.keyLifeSpan = time.Duration(conf.MaxKeyAge) * 24 * time.Hour
	}

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

	// Prepare our TLS settings
	addrPort := fmt.Sprintf("%s:%d", conf.Addr, conf.Port)
	tlsConf, err := getTLSConfig(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer conf.db.Close()
	server := &http.Server{
		Addr:      addrPort,
		TLSConfig: tlsConf,
	}

	// Start our listener service
	log.Printf("Starting HTTPS server on %s", addrPort)
	err = server.ListenAndServeTLS(conf.SSLCert, conf.SSLKey)
	if err != nil {
		log.Fatalf("Listener service: %v", err)
	}
}

func init() {
	//if cfgFile != "" { // enable ability to specify config file via flag
	//	viper.SetConfigFile(cfgFile)
	//}

	viper.SetConfigName("cursed") // name of config file (without extension)
	viper.AddConfigPath("/opt/curse/etc/")
	viper.AddConfigPath("/etc/curse/")
	viper.AddConfigPath(".")
	viper.ReadInConfig()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}

	viper.SetDefault("addr", "127.0.0.1")
	viper.SetDefault("cakeyfile", "/opt/curse/etc/user_ca")
	viper.SetDefault("dbfile", "/opt/curse/etc/cursed.db")
	viper.SetDefault("duration", 2*60)
	viper.SetDefault("extensions", []string{"permit-pty"})
	viper.SetDefault("forcecmd", false)
	viper.SetDefault("maxkeyage", 90)
	viper.SetDefault("port", 81)
	viper.SetDefault("requireclientip", true)
	viper.SetDefault("sslca", "/opt/curse/etc/server.crt")
	viper.SetDefault("sslcert", "/opt/curse/etc/server.crt")
	viper.SetDefault("sslkey", "/opt/curse/etc/server.key")
	viper.SetDefault("userheader", "REMOTE_USER")
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

func getConf() (*config, error) {
	// Read config into a struct
	var conf config
	err := viper.Unmarshal(&conf)
	if err != nil {
		return nil, fmt.Errorf("Unable to read config into struct: %v", err)
	}
	// Hardcoding the DB bucket name
	conf.bucketName = []byte("pubkeybirthdays")

	// Require TLS mutual authentication for security
	if conf.SSLCA == "" || conf.SSLKey == "" || conf.SSLCert == "" {
		return nil, fmt.Errorf("sslca, sslkey, and sslcert are required fields")
	}

	// Expand $HOME into service user's home path
	conf.DBFile = expandHome(conf.DBFile)

	// Check our certificate extensions (permissions) for validity
	var errSlice []error
	conf.exts, errSlice = validateExtensions(conf.Extensions)
	if len(errSlice) > 0 {
		for _, err := range errSlice {
			log.Printf("%v", err)
		}
	}

	// Compile our user-matching regex (usernames are limited to 32 characters, must start
	// with a-z or _, and contain only these characters: a-z, 0-9, - and _
	conf.userRegex = regexp.MustCompile(`(?i)^[a-z_][a-z0-9_-]{0,31}$`)

	return &conf, nil
}
