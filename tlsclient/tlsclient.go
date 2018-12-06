package main

// This began it's life as github.com/bifurcation/mint/bin/mint-client

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/bifurcation/mint"
)

var addr string
var dtls bool
var dontValidate bool

type Msg struct {
	RecType uint16
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

const (
	rec_eom       = 0
	rec_nextproto = 1
	rec_aead      = 4
	rec_cookie    = 5
	rec_ntpserver = 6
)

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}

func hasBit(n uint16, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}

func main() {
	alpn := "ntske/1"

	c := mint.Config{}
	c.NextProtos = []string{alpn}

	flag.StringVar(&addr, "addr", "localhost:4430", "port")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.Parse()
	if dontValidate {
		c.InsecureSkipVerify = true
	}

	ke, err := Connect(addr, c)
	if err != nil {
		fmt.Printf("Couldn't connect to %s\n", addr)
		return
	}

	err = ke.readReply()
	if err != nil {
		fmt.Printf("parseMsg error: %v\n", err)
		return
	}

	fmt.Printf("data: %v\n", ke.meta)

	// 4.2. in https://tools.ietf.org/html/draft-dansarie-nts-00
	label := "EXPORTER-network-time-security/1"

	// The per-association context value SHALL consist of the following
	// five octets:
	//
	// The first two octets SHALL be zero (the Protocol ID for NTPv4).
	//
	// The next two octets SHALL be the Numeric Identifier of the
	// negotiated AEAD Algorithm in network byte order. Typically
	// 0x0f for AES-SIV-CMAC-256.
	//
	// The final octet SHALL be 0x00 for the C2S key and 0x01 for the
	// S2C key.
	s2c_context := []byte("\x00\x00\x00")
	binary.BigEndian.PutUint16(s2c_context, ke.meta.Algo)
	s2c_context = append(s2c_context, 0x00)

	c2s_context := []byte("\x00\x00\x00")
	binary.BigEndian.PutUint16(c2s_context, ke.meta.Algo)
	c2s_context = append(s2c_context, 0x01)

	var keylength = 32
	// exported keying materials
	if ke.meta.C2s_key, err = ke.conn.ComputeExporter(label, c2s_context, keylength); err != nil {
		panic("bork")
	}
	if ke.meta.S2c_key, err = ke.conn.ComputeExporter(label, s2c_context, keylength); err != nil {
		panic("bork")
	}

	b, err := json.Marshal(ke.meta)
	err = ioutil.WriteFile(datafn, b, 0644)
	fmt.Printf("Wrote %s\n", datafn)
}
