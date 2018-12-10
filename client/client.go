package main

import (
	"crypto/tls"
	"flag"
	"fmt"

	"../ntske"
	"github.com/beevik/ntp"
)

var addr string
var dtls bool
var dontValidate bool

const datafn = "../ke.json"

func main() {
	flag.StringVar(&addr, "addr", "localhost:4430", "adress:port")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.Parse()

	c := tls.Config{}
	if dontValidate {
		c.InsecureSkipVerify = true
	}

	ke, err := ntske.Connect(addr, c)
	if err != nil {
		fmt.Printf("Couldn't connect to %s\n", addr)
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

	ntpTime, err := ntp.Time("localhost")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("Network time: %vx\n", ntpTime)
}
