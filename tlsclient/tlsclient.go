package main

// This began it's life as github.com/bifurcation/mint/bin/mint-client

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/bifurcation/mint"
)

var addr string
var dtls bool
var dontValidate bool

type Record struct {
	Type    uint16
	BodyLen uint16
}

type Data struct {
	C2s_key []byte
	S2c_key []byte
	Server  [][16]byte
	Cookie  [][]byte
	Algo    uint16 // AEAD
}

const datafn = "../ke.json"

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}

func hasBit(n uint16, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}

func main() {
	flag.StringVar(&addr, "addr", "localhost:4430", "adress:port")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.Parse()

	c := mint.Config{}
	if dontValidate {
		c.InsecureSkipVerify = true
	}

	ke, err := Connect(addr, c)
	if err != nil {
		fmt.Printf("Couldn't connect to %s\n", addr)
		return
	}

	ke.StartMessage()
	ke.Algorithm()
	ke.Write()

	err = ke.Read()
	if err != nil {
		fmt.Printf("ReadReply error: %v\n", err)
		return
	}

	fmt.Printf("data: %v\n", ke.meta)

	ke.ExportKeys()

	b, err := json.Marshal(ke.meta)
	err = ioutil.WriteFile(datafn, b, 0644)
	fmt.Printf("Wrote %s\n", datafn)
}
