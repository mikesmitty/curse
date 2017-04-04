// Copyright © 2017 Michael Smith <mikejsmitty@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"fmt"
	"os"

	"github.com/mikesmitty/curse/jinx/jinxlib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verbose bool

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "jinx",
	Short: "SSH certificate client",
	Long: `JINX is a client to the CURSE SSH certificate authority.
It is used to provide short-lived SSH certificates in place of semi-permanent SSH pubkeys
in authorized_keys files, which are difficult to manage at scale and over long periods
of time.`,
	Run: func(cmd *cobra.Command, args []string) {
		jinxlib.Jinx(verbose, args)
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	//RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.jinx.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose mode")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	//if cfgFile != "" { // enable ability to specify config file via flag
	//	viper.SetConfigFile(cfgFile)
	//}

	viper.SetConfigName("jinx") // name of config file (without extension)
	viper.AddConfigPath("/etc/jinx")
	viper.AddConfigPath("$HOME/.jinx/")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		//fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	viper.SetDefault("autogenkeys", true)
	viper.SetDefault("bastionip", "")
	viper.SetDefault("insecure", false)
	viper.SetDefault("keygenbitsize", 2048)
	viper.SetDefault("keygenpubkey", "$HOME/.ssh/id_jinx.pub")
	viper.SetDefault("keygentype", "ed25519")
	viper.SetDefault("promptusername", false)
	viper.SetDefault("pubkey", "$HOME/.ssh/id_ed25519.pub")
	viper.SetDefault("sshuser", "root") // FIXME Need to revisit this?
	viper.SetDefault("sslcafile", "/etc/jinx/ca.crt")
	viper.SetDefault("sslcertfile", "$HOME/.jinx/client.crt")
	viper.SetDefault("sslkeycurve", "p384")
	viper.SetDefault("sslkeyfile", "$HOME/.jinx/client.key")
	viper.SetDefault("timeout", 30)
	viper.SetDefault("urlauth", "https://localhost:444/auth/")
	viper.SetDefault("urlcurse", "https://localhost:444/")
	viper.SetDefault("usesslca", true)
}
