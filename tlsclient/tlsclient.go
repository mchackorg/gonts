package main

// This began it's life as github.com/bifurcation/mint/bin/mint-client

import (
	"flag"
	"fmt"

	"github.com/bifurcation/mint"
)

var addr string
var dtls bool
var dontValidate bool

func main() {
	c := mint.Config{}

	flag.StringVar(&addr, "addr", "localhost:4430", "port")
	flag.BoolVar(&dtls, "dtls", false, "use DTLS")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.Parse()
	if dontValidate {
		c.InsecureSkipVerify = true
	}
	network := "tcp"
	if dtls {
		network = "udp"
	}
	conn, err := mint.Dial(network, addr, &c)

	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	// offered := []string{"ntske/1"}
	// a, err := mint.ALPNNegotiation(nil, offered, offered)
	// fmt.Printf("__ %s __\n", a)

	// 4.2. in https://tools.ietf.org/html/draft-dansarie-nts-00
	label := "EXPORTER-network-time-security/1"
	// 0x000f = AES-SIV-CMAC-256
	s2c_context := []byte("\x00\x00\x00\x0f\x00")
	c2s_context := []byte("\x00\x00\x00\x0f\x01")
	keyLength := 32

	// exported keying materials
	var c2s_key, s2c_key []byte
	if c2s_key, err = conn.ComputeExporter(label, c2s_context, keyLength); err != nil {
		panic("bork")
	}
	if s2c_key, err = conn.ComputeExporter(label, s2c_context, keyLength); err != nil {
		panic("bork")
	}

	fmt.Printf("c2s: %v\n", c2s_key)
	fmt.Printf("s2c: %v\n", s2c_key)
}
