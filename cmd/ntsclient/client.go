package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/beevik/ntp"
	"github.com/mchackorg/gonts/ntske"
)

var addr string
var dtls bool
var dontValidate bool
var caFile string

const datafn = "../ke.json"

func main() {
	flag.StringVar(&addr, "addr", "localhost:4430", "adress:port")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.StringVar(&caFile, "cafile", "", "Authority Certificates file")
	flag.Parse()

	//	TLS 1.3 is available only on an opt-in basis in Go 1.12. To
	//	enable it, set the GODEBUG environment variable
	//	(comma-separated key=value options) such that it includes
	//	"tls13=1". To enable it from within the process, set the
	//	environment variable before any use of TLS:

	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	certPool := x509.NewCertPool()
	if caFile == "" {
		certPool, _ = x509.SystemCertPool()
	} else {
		certs, err := ioutil.ReadFile(caFile)
		if err != nil {
			fmt.Println("Failed to append %s to certPool: %v", caFile, err)
		}

		if ok := certPool.AppendCertsFromPEM(certs); !ok {
			fmt.Println("No certs appended")
		}
	}

	c := tls.Config{RootCAs: certPool}
	if dontValidate {
		c.InsecureSkipVerify = true
	}

	ke, err := ntske.Connect(addr, c)
	if err != nil {
		fmt.Printf("Couldn't connect to %s (%s)\n", addr, err)
		return
	}

	ke.StartMessage()
	ke.Algorithm()
	ke.Write()

	err = ke.Read()
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}

	// Check that we have complete data. It's OK
	// if we don't fill in meta.Server --- this
	// means the client should use the same IP
	// address as the NTS-KE server.

	if len(ke.Meta.Cookie) == 0 {
		fmt.Printf("We got no cookie from server!")
		return
	}

	if ke.Meta.Algo != ntske.AES_SIV_CMAC_256 {
		fmt.Printf("We got an algorithm we can't handle.`")
		return
	}

	ke.ExportKeys()

	fmt.Printf("NTS-KE negotiated data: %#v\n", ke.Meta)

	ntpTime, err := ntp.QueryWithOptions(ke.Meta.Server, ntp.QueryOptions{Port: int(ke.Meta.Port)})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Network time: %vx\n", ntpTime)
}
