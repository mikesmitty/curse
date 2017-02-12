package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	caKeyFile string
	dur       time.Duration
	port      int
)

func main() {
	// Parse command-line options
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: ./cursed -port=8000\n")
		flag.PrintDefaults()
	}

	flag.DurationVar(&dur, "dur", 2*time.Minute, "The duration of the certificate (in seconds)")
	flag.IntVar(&port, "port", 8000, "The port on which to listen")
	flag.StringVar(&caKeyFile, "cakey", "test_keys/user_ca", "Key file containing the CA private key")

	caKey, err := loadCAKey(caKeyFile)
	if err != nil {
		log.Fatal("Couldn't load CA key: ", err)
	}

	// Start web service
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rawPubKey := r.PostFormValue("k")
		if rawPubKey != "" {
			log.Printf("Signing request: |%s|", rawPubKey)

			exts := make(map[string]string)

			// Enable all extensions for testing DEBUG
			exts["permit-X11-forwarding"] = ""
			exts["permit-agent-forwarding"] = ""
			exts["permit-port-forwarding"] = ""
			exts["permit-pty"] = ""
			exts["permit-user-rc"] = ""

			certConf := certConfig{
				certType: ssh.UserCert,
				//dur:        time.Second * dur,
				dur:        dur,
				exts:       exts,
				principals: []string{"root"}, //DEBUG
				srcAddr:    "1.2.3.4",        //DEBUG
			}

			key, err := signPubKey(caKey, []byte(rawPubKey), certConf)
			if err != nil {
				log.Printf("%v", err)
			} else {
				w.Write(ssh.MarshalAuthorizedKey(key))
			}
		}

	})
	log.Printf("Starting HTTP server on %d", port)
	err = http.ListenAndServe(":"+strconv.Itoa(port), nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
