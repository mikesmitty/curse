// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	caKeyFile string
	cfgFile   string
	durInt    int
	duration  time.Duration
	port      int
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "cursed",
	Short: "SSH certificate signing daemon",
	Long:  `CURSE is an SSH certificating signing server, built as an alternative to Netflix's BLESS tool, but without a dependency on AWS`,
	Run: func(cmd *cobra.Command, args []string) {

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
					certType:   ssh.UserCert,
					command:    "echo test",
					duration:   duration,
					extensions: exts,
					keyId:      "key_id goes here", //DEBUG
					principals: []string{"root"},   //DEBUG
					srcAddr:    "1.2.3.4",          //DEBUG
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
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Printf("%v", err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVar(&caKeyFile, "cakey", "test_keys/user_ca", "File path of the CA private key to be used for signing")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cursed.yaml)")
	RootCmd.PersistentFlags().IntVar(&durInt, "dur", 2*60, "Duration of certificate validity, in seconds")
	RootCmd.PersistentFlags().IntVar(&port, "port", 8000, "Port to listen on")

	// Convert our duration from int to time.Duration
	duration = time.Duration(durInt) * time.Second
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName(".cursed") // name of config file (without extension)
	viper.AddConfigPath("$HOME")   // adding home directory as first search path
	viper.AutomaticEnv()           // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file:", viper.ConfigFileUsed())
	}
}
