package main

import (
	"net"
	"os"
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

func validIP(ip string) bool {
	res := net.ParseIP(ip)

	return res != nil
}
