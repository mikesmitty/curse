package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

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
		return "", fmt.Errorf("Unable to find bastion IP: %v", err)
	}

	for _, ip := range addrs {
		ipNet := strings.Split(ip.String(), "/")
		if !localIPs.MatchString(ipNet[0]) {
			return ipNet[0], nil
		}
	}

	return "", fmt.Errorf("Found no public IP addresses")
}
