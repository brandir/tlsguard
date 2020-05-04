// Time-stamp: <2020-05-04 16:33:48 (elrond@rivendell) dnslookup.go>

// https://github.com/brandir/tlsguard

// Setting GODEBUG=netdns=9 gives more insight how go is doing that.
// Go's stdlib either uses the C stdlib (via cgo) or a pure DNS resolver.
// 
// Output for elrond@rivendell is the following
// 
// go package net: dynamic selection of DNS resolver
// go package net: hostLookupOrder(google.com) = cgo
// google.com. IN A 2a00:1450:4016:805::200e
// google.com. IN A 172.217.23.78


package main

import (
	"net"
	"fmt"
	"os"
)

func main() {
	ips, err := net.LookupIP("google.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Printf("google.com. IN A %s\n", ip.String())
	}
}
