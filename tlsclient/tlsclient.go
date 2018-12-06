package main

// This began it's life as github.com/bifurcation/mint/bin/mint-client

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"../ntske"
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

	ke.ExportKeys()

	fmt.Printf("Negotiated data: %#v\n", ke.Meta)

	b, err := json.Marshal(ke.Meta)
	err = ioutil.WriteFile(datafn, b, 0644)
	fmt.Printf("Wrote %s\n", datafn)
}
