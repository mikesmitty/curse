package jinxlib

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
	"strings"

	"github.com/bgentry/speakeasy"
)

func getPathByFilename(path string) string {
	e := strings.Split(path, "/")
	n := len(e) - 1
	dir := strings.Join(e[:n], "/")

	return dir
}

func expandHome(path string) string {
	// Swap out $HOME for service user's home dir in path
	home := os.Getenv("HOME")
	if strings.HasPrefix(path, "$HOME") && home != "" {
		path = strings.Replace(path, "$HOME", home, 1)
	}

	return path
}

func getBastionIP() (string, error) {
	// Compile our private address space/loopback address matching regex
	localIPs := regexp.MustCompile(`^(fe80|::1|127\.|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)`)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// FIXME add some logging level verbosity here
		return "", fmt.Errorf("unable to find bastion ip: %v", err)
	}

	for _, ip := range addrs {
		ipNet := strings.Split(ip.String(), "/")
		if !localIPs.MatchString(ipNet[0]) {
			return ipNet[0], nil
		}
	}

	return "", fmt.Errorf("found no public ip addresses")
}

func getUserPass(conf *config) (string, string, error) {
	var (
		un  string
		err error
	)

	// Nag-mode for inadvertent/malicious insecure setting
	if conf.Insecure {
		fmt.Println("warning, your password is about to be sent insecurely. ctrl+c to quit")
	}

	if !conf.PromptUsername {
		u, err := user.Current()
		if err == nil {
			un = u.Username
		}
	}

	// Read in our username and password
	if un == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("username: ")
		un, err = reader.ReadString('\n')
		if err != nil {
			return "", "", fmt.Errorf("Input error: %v", err)
		}
		un = strings.TrimSpace(un)
	}

	pass, err := speakeasy.Ask("password: ")
	if err != nil {
		return "", "", fmt.Errorf("shell error: %v", err)
	}

	return un, pass, nil
}
