package main

import "net"

func validIP(ip string) bool {
	res := net.ParseIP(ip)

	return res != nil
}
