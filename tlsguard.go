/* Time-stamp: <2020-05-04 16:36:05 (elrond@rivendell) tlsguard.go>
 *
 * tlsguard project, created 04/24/2020
 *
 * https://github.com/brandir/tlsguard
 *
 * TLS cipher check implementation in Go.
 * Many ideas from the testssl.sh program, cf. https://github.com/drwetter/testssl.sh/blob/3.1dev/testssl.sh
 */

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	// admin information
	author = "dmon"
	version = "1.0"
	cdate = "04/24/2020"
	carch = "kali"
	program = "tlsguard"
	github = "https://github.com/brandir/tlsguard"
	
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

// Variables and function for color codes for highlighted output.
var (
	Info = teal
	Log  = purple
	Warn = yellow
	Fata = red
	User = magenta
)

var (
	black   = Color("\033[1;30m%s\033[0m")
        red     = Color("\033[1;31m%s\033[0m")
        green   = Color("\033[1;32m%s\033[0m")
        yellow  = Color("\033[1;33m%s\033[0m")
        purple  = Color("\033[1;34m%s\033[0m")
        magenta = Color("\033[1;35m%s\033[0m")
        teal    = Color("\033[1;36m%s\033[0m")
        white   = Color("\033[1;37m%s\033[0m")
)

func Color(colorstring string) func(...interface{}) string {
        sprint := func(args ...interface{}) string {
                return fmt.Sprintf(colorstring, fmt.Sprint(args...))
        }
        return sprint
}
	
// Create a dictionary with TLS cipher information using a map.
// Structure: hexcode -> cert type | cipher name | tls version support
func createCipherDictionary() map[string][]string {
        m := make(map[string][]string)
        m["0xc02b"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS1.2"}
        m["0xc02c"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS1.2"}
        m["0xc0ac"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", "TLS1.2"}
	m["0xc0ad"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", "TLS1.2"}
	m["0xc0ae"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", "TLS1.2"}
	m["0xc0af"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", "TLS1.2"}
	m["0xc023"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0xc024"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "TLS1.2"}

	m["0xc009"] = []string{"ECDSA", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0xc00a"] = []string{"ECDDA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}

	m["0xc02f"] = []string{"RSA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0xc030"] = []string{"RSA", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS1.2"}
	m["0x009e"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0x009f"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS1,2"}
	m["0xc09e"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_128_CCM", "TLS1,2"}
	m["0xc09f"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_256_CCM", "TLS1.2"}
	m["0xc0a2"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_128_CCM_8", "TLS1.2"}
	m["0xc0a3"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_256_CCM_8", "TLS1,2"}
	m["0xc027"] = []string{"RSA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0xc028"] = []string{"RSA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS1.2"}
	m["0x0067"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0x006b"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "TLS1.2"}

	m["0xc013"] = []string{"RSA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0xc014"] = []string{"RSA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0x0033"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0x0039"] = []string{"RSA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}

	m["0x00a2"] = []string{"DSA", "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0x00a3"] = []string{"DSA", "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "TLS1.2"}
	m["0x0040"] = []string{"DSA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0x006a"] = []string{"DSA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "TLS1.2"}

	m["0x0032"] = []string{"DSA", "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1,1", "TLS1.0"}
	m["0x0038"] = []string{"DSA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}

	m["0x00a4"] = []string{"DSA", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0x00a5"] = []string{"DSA", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS1.2"}
	m["0x003e"] = []string{"DSA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0x0068"] = []string{"DSA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "TLS1.2"}

	m["0x0030"] = []string{"DSA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0x0036"] = []string{"DSA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1,0"}

	m["0x00a4"] = []string{"DSA-DH", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0x00a5"] = []string{"DSA-DH", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "TLS1.2"}
	m["0x003e"] = []string{"DSA-DH", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0x0068"] = []string{"DSA-DH", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "TLS1.2"}

	m["0x0030"] = []string{"DSA-DH", "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0x0036"] = []string{"DSA-DH", "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}

	m["0x00a0"] = []string{"RSA-DH", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0x00a1"] = []string{"RSA-DH", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "TLS1.2"}
	m["0x003f"] = []string{"RSA-DH", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0x0069"] = []string{"RSA-DH", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "TLS1.2"}

	m["0x0031"] = []string{"RSA-DH", "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0x0037"] = []string{"RSA-DH", "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}

	m["0xc02d"] = []string{"ECDSA-ECDH", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0xc02e"] = []string{"ECDSA-ECDH", "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "TLS1.2"}
	m["0xc025"] = []string{"ECDSA-ECDH", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0xc026"] = []string{"ECDSA-ECDH", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "TLS1.2"}

	m["0xc004"] = []string{"ECDSA-ECDH", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0xc005"] = []string{"ECDSA-ECDH", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}

	m["0xc031"] = []string{"RSA-ECDH", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "TLS1.2"}
	m["0xc032"] = []string{"RSA-ECDH", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "TLS1.2"}
	m["0xc029"] = []string{"RSA-ECDH", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "TLS1.2"}
	m["0xc02a"] = []string{"RSA-ECDH", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "TLS1.2"}

	m["0xc00e"] = []string{"RSA-ECDH", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}
	m["0xc00f"] = []string{"RSA-ECDH", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "TLS1.2", "TLS1.1", "TLS1.0"}

	m["0x1301"] = []string{"RSA", "ECDSA", "TLS_AES_128_GCM_SHA256", "TLS1.3"}
	m["0x1302"] = []string{"RSA", "ECDSA", "TLS_AES_256_GCM_SHA384", "TLS1.3"}
	m["0x1304"] = []string{"RSA", "ECDSA", "TLS_AES_128_CCM_SHA256", "TLS1.3"}
	m["0x1305"] = []string{"RSA", "ECDSA", "TLS_AES_128_CCM_8_SHA256", "TLS1.3"}
	
	return m
}

func getCipherHex(cipher_hex string, tls_dict map[string][]string)[]string {
	if res, found := tls_dict[cipher_hex]; found {
		fmt.Println(res)
		return res
	} else {
		return res
	}
}

// Get the rDNS entry
func getrDNSentry(host string) string {
	fmt.Println(host)
	return ""
}

// Checks if the hostname can be looked up.
func validateHostname(hostname string) bool {
	addr, err := net.LookupHost(hostname)
	if err != nil || len(addr) < 1 {
		return false
	} else {
		return true
	}
}

// Look up the local node name.
func getNodename() string {
	nodename, err := os.Hostname()
	if err != nil {
		panic(err)
	} else {
		return nodename
	}
}

// Look up the local IP.
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	} else {
		for _, address := range addrs {
			// check the address type and ignore the loopback IP
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return ""
}

// Look up the public IP.
func getPublicIP() string {
	url := "https://api.ipify.org?format=text"
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(ip)
}

// Get formatted time string, e.g. 2020-04-29 17:52:55.
func getTime() string {
	t := time.Now()
        ts := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	return ts
}

// Print banner and version information.
func printBanner() string {
	fmt.Printf("--- %s V%s [(c) %s %s <%s>] ---\n", program, version, author, cdate, github)
	return ""
}

func main () {

	// Command line options processing.
	var uri string
	//	printBanner()

	//	if validateHostname("www.freebsd.org") {
	//		fmt.Printf("www.freebsd.org found!\n")
	//	} else {
	//		fmt.Printf("www.freebsd.org not found!\n")
	//	}
	// fmt.Println("... createCipherDictionary()")
	// cipher_dict := createCipherDictionary()
	// fmt.Println("... getCipherHex()")
	//	getCipherHex("0xc009", cipher_dict)
	// getCipherHex("0x0036", cipher_dict)
	// getCipherHex("0x1301", cipher_dict)
	fmt.Println(Info(getNodename()))
	fmt.Println(Log(getLocalIP()))
	fmt.Println(Warn(getPublicIP()))

	banner := flag.Bool("banner", false, "Display banner and version of tlsguard\n")
	b := flag.Bool("b", false, "Display banner and version of tlsguard\n")
	log := flag.Bool("log", false, "Log output to 'tlsguard.log'\n")
        l := flag.Bool("l", false, "Log output to 'tlsguard.log'\n")
        test := flag.Bool("test", false, "Option for test & development [default: off]\n")
        t := flag.Bool("t", false, "Option for test & development [default: off]\n")
        flag.StringVar(&uri, "uri", "", "Input URI to be checked\n")
        flag.StringVar(&uri, "u", "", "Input URI to be checked\n")
        verbose := flag.Bool("verbose", false, "Verbosity level [default: off]\n")
        v :=  flag.Bool("v", false, "Verbosity level [default: off]\n")

	flag.Usage = func() {
                fmt.Printf("Usage: %s [options] <URI>\n", os.Args[0])
                fmt.Printf("Check TLS protocol and cipher details.\n")
                fmt.Println()
                fmt.Printf("Mandatory arguments for long options are mandatory for short options too.\n")
                fmt.Printf("    -h, --help            display this help and exit\n")
                fmt.Printf("    -b, --banner          display banner and version of %s\n")
                fmt.Printf("    -V, --version         display version and exit\n")
                fmt.Println()
                fmt.Printf("    -a, --all             perform every action\n")
                fmt.Printf("    -l, --log <logfile>   log stdout to specified <logfile>\n")
                fmt.Printf("    -t, --test            option for testing only\n")
                fmt.Printf("    -u, --uri             uri to be checked\n")
                fmt.Printf("    -v, --verbose         be verbose\n")
                //              flag.PrintDefaults()
        }
        flag.Parse()

	fmt.Println(Info(getTime()))
	
	if *banner || *b {
		printBanner()
	}
	if *log || *l {
                fmt.Printf("Logging to 'tlsguard.log' ...\n")
        }
        if *test || *t {
                fmt.Printf("Running in test mode ...\n")
        }
        if *verbose || *v {
                fmt.Printf("Verbose mode is on ...\n")
        }
        if len(uri) > 0 {
                fmt.Printf("Checking URI '%s' ...\n", uri)
        }

}

