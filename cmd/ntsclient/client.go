package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

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

	// TODO use the negotiated NTP server in ke.Meta.Server if any
	addrNoPort := addr[:strings.IndexByte(addr, ':')]

	ntpTime, err := ntp.Time(addrNoPort)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Network time: %vx\n", ntpTime)
}
