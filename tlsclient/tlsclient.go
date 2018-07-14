package main

// This began it's life as github.com/bifurcation/mint/bin/mint-client

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"

	"github.com/bifurcation/mint"
)

var addr string
var dtls bool
var dontValidate bool

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}

type nextproto_ntske struct {
	Rectype uint16
	Bodylen uint16
	Body    []uint16
}

func nextprotoRec() *nextproto_ntske {
	rec := new(nextproto_ntske)
	rec.Rectype = 1
	rec.Rectype = setBit(rec.Rectype, 15)
	rec.Body = []uint16{0}
	rec.Bodylen = 2
	return rec
}

type aead_ntske struct {
	Rectype uint16
	Bodylen uint16
	Body    []uint16
}

func aeadRec() *aead_ntske {
	rec := new(aead_ntske)
	rec.Rectype = 4
	rec.Rectype = setBit(rec.Rectype, 15)
	rec.Body = []uint16{15}
	rec.Bodylen = 2
	return rec
}

type server_ntske struct {
	Rectype uint16
	Bodylen uint16
	Body    [][16]byte
}

func serverRec() *server_ntske {
	rec := new(server_ntske)
	rec.Rectype = 6
	rec.Rectype = setBit(rec.Rectype, 15)
	rec.Body = [][16]byte{{1}}
	rec.Bodylen = 2
	return rec
}

type end_ntske struct {
	Rectype uint16
	Bodylen uint16
}

func endRec() *end_ntske {
	rec := new(end_ntske)
	rec.Rectype = 0
	rec.Rectype = setBit(rec.Rectype, 15)
	rec.Bodylen = 0
	return rec
}

type cookie_ntske struct {
	Rectype uint16
	Bodylen uint16
	Body    []uint32
}

func cookieRec() *cookie_ntske {
	rec := new(cookie_ntske)
	rec.Rectype = 5
	rec.Body = []uint32{4711}
	rec.Bodylen = 4
	return rec
}

func main() {
	alpn := "ntske/1"

	c := mint.Config{}
	c.NextProtos = []string{alpn}

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

	state := conn.ConnectionState()
	if state.NextProto != alpn {
		panic("server not doing ntske/1")
	}

	buf := new(bytes.Buffer)

	rec := nextprotoRec()
	err = binary.Write(buf, binary.BigEndian, rec)
	if err != nil {
		log.Fatal(err)
	}
	rec2 := aeadRec()
	err = binary.Write(buf, binary.BigEndian, rec2)
	if err != nil {
		log.Fatal("Couldn't binary write 2")
	}
	rec3 := endRec()
	err = binary.Write(buf, binary.BigEndian, rec3)
	if err != nil {
		log.Fatal("Couldn't binary write 3")
	}
	fmt.Printf("%v\n", buf)

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
