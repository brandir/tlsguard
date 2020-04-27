/* Time-stamp: <2020-04-24 18:40:59 (jgalt@kali) tlsguard.go>
 *
 * tlsguard project, created 04/24/2020
 *
 * TLS cipher check implementation in Go.
 * Many ideas from the testssl.sh program, cf. https://github.com/drwetter/testssl.sh/blob/3.1dev/testssl.sh
 */

package main

import (
	"fmt"
	"net"
)

const (
	// admin information
	author = "dmon"
	version = "1.0"
	cdate = "04/24/2020"
	carch = "kali"
	program = "tlsguard"
	
	// cf. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
	
	// TLS Cipher Suites for ECDSA Certificates
	
	// TLS 1.2 servers that are configured with ECDSA certificates maybe configured to support the following
	// cipher suites, which are only supported by TLS 1.2:
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM        uint16 = 0xc0ac
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM        uint16 = 0xc0ad
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8      uint16 = 0xc0ae
	TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8      uint16 = 0xc0af
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 uint16 = 0xc023
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 uint16 = 0xc024
	
	// TLS servers may be configured to support the following cipher suites when ECDSA certificates are used
	// with TLS versions 1.2, 1.1, or 1.0
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA21  uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	
	// TLS Cipher suites for RSA Certificates
	
	// TLS 1.2 servers that are configured with RSA certificates may be configured to support the following
	// cipher suites.
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     uint16 = 0x009e
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     uint16 = 0x009f
	TLS_DHE_RSA_WITH_AES_128_CCM            uint16 = 0xc09e
	TLS_DHE_RSA_WITH_AES_256_CCM            uint16 = 0xc09f
	TLS_DHE_RSA_WITH_AES_128_CCM_8          uint16 = 0xc0a2
	TLS_DHE_RSA_WITH_AES_256_CCM_8          uint16 = 0xc0a3
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   uint16 = 0xc028
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256     uint16 = 0x0067
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256     uint16 = 0x006B
	
	// TLS servers may be configured to support the following cipher suites when RSA certificates are used
	// with TLS versions 1.2, 1.1, or 1.0
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA        uint16 = 0x0033
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA        uint16 = 0x0039

	// TLS Cipher suites for DSA Certificates
	
	// TLS 1.2 servers that are configured with DSA certificates may be configured to support the following
	// cipher suites
	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256     uint16 = 0x00a2
	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384     uint16 = 0x00a3
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256     uint16 = 0x0040
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256     uint16 = 0x006a
	
	// TLS servers may be configured to support the following cipher suites when DSA certificates are used
	// with TLS versions 1.2, 1.1, or 1.0
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA        uint16 = 0x0032
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA        uint16 = 0x0038

	// TLS Cipher suites for DH Certificates
	
	// TLS 1.2 servers that are configured with DSA-signed DH certificates may be configured to support the
	// following cipher suites
	TLS_DH_DSS_WITH_AES_128_GCM_SHA256      uint16 = 0x00a4
	TLS_DH_DSS_WITH_AES_256_GCM_SHA384      uint16 = 0x00a5
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256      uint16 = 0x003e
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256      uint16 = 0x0068
	
	// TLS servers may be configured to support the following cipher suites when DSA-signed DH certificates
	// are used with TLS versions 1.2, 1.1, or 1.0
	TLS_DH_DSS_WITH_AES_128_CBC_SHA         uint16 = 0x0030
	TLS_DH_DSS_WITH_AES_256_CBC_SHA         uint16 = 0x0036
	
	// TLS 1.2 servers that are configured with RSA-signed DH certificates may be configured to support the
	// following cipher suites
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256      uint16 = 0x00a0
	TLS_DH_RSA_WITH_AES_256_GCM_SHA384      uint16 = 0x00a1
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256      uint16 = 0x003f
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256      uint16 = 0x0069
	
	// TLS servers may be configured to support the following cipher suites when RSA-signed DH certificates
	// are used with TLS versions 1.2, 1.1, or 1.0
	TLS_DH_RSA_WITH_AES_128_CBC_SHA         uint16 = 0x0031
	TLS_DH_RSA_WITH_AES_256_CBC_SHA         uint16 = 0x0037

	// TLS Cipher suites for ECDH Certificates
	
	// TLS 1.2 servers that are configured with ECDSA-signed ECDH certificates may be configured to support
	// the following cipher suite
	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256  uint16 = 0xc02d
	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384  uint16 = 0xc02e
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  uint16 = 0xc025
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  uint16 = 0xc026
	
	// TLS servers may be configured to support the following cipher suites when ECDSA-signed ECDH certificates
	// are used with TLS versions 1.2, 1.1, or 1.0
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA     uint16 = 0xc004
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA     uint16 = 0xc005
	
	// TLS 1.2 servers that are configured with RSA-signed ECDH certificates may be configured to support
	// the following cipher suites
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256    uint16 = 0xc031
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384    uint16 = 0xc032
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256    uint16 = 0xc029
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384    uint16 = 0xc02a
	
	// TLS servers may be configured to support the following cipher suites when RSA-signed ECDH certificates
	// are used with TLS versions 1.2, 1.1, or 1.0
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA       uint16 = 0xc00e
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA       uint16 = 0xc00f
	
	// TLS Cipher suites for TLS 1.3
	
        // TLS 1.3 servers may be configured to support the following cipher suites
	TLS_AES_128_GCM_SHA256                  uint16 = 0x1301
	TLS_AES_256_GCM_SHA384                  uint16 = 0x1302
	TLS_AES_128_CCM_SHA256                  uint16 = 0x1304
	TLS_AES_128_CCM_8_SHA256                uint16 = 0x1305
)

// Checks if the hostname can be looked up.
func validateHostname(hostname string) bool {
	addr, err := net.LookupHost(hostname)
	if err != nil || len(addr) < 1 {
		return false
	} else {
		return true
	}
}

func main () {
	fmt.Printf("--- %s V%s [(c) %s %s)] ---\n", program, version, author, cdate)

	if validateHostname("www.freebsd.org") {
		fmt.Printf("www.freebsd.org found!\n")
	} else {
		fmt.Printf("www.freebsd.org not found!\n")
	}
}

