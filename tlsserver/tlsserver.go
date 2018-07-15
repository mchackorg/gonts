package main

// This began it's life as github.com/bifurcation/mint/bin/mint-server

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/bifurcation/mint"
)

var port string

func main() {
	var config mint.Config
	config.SendSessionTickets = true
	config.ServerName = "localhost"
	config.NextProtos = []string{"ntske/1"}

	priv, cert, err := mint.MakeNewSelfSignedCert("localhost", mint.RSA_PKCS1_SHA256)
	config.Certificates = []*mint.Certificate{
		{
			Chain:      []*x509.Certificate{cert},
			PrivateKey: priv,
		},
	}
	config.Init(false)

	flag.StringVar(&port, "port", "4430", "port")
	flag.Parse()

	service := "0.0.0.0:" + port
	listener, err := mint.Listen("tcp", service, &config)

	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}
func handleClient(conn net.Conn) {
	defer conn.Close()

	msg := new(bytes.Buffer)

	var rec []uint16 // rectype, bodylen, body
	var octets []uint8

	// nextproto
	rec = []uint16{1, 2, 0x00} // NTPv4
	rec[0] = setBit(rec[0], 15)
	_ = binary.Write(msg, binary.BigEndian, rec)

	// AEAD
	rec = []uint16{4, 2, 0x0f} // AES-SIV-CMAC-256
	rec[0] = setBit(rec[0], 15)
	_ = binary.Write(msg, binary.BigEndian, rec)

	// ntp server
	rec = []uint16{6, 16} // 1 server addr == 16 bytes
	rec[0] = setBit(rec[0], 15)
	_ = binary.Write(msg, binary.BigEndian, rec)
	octets := []uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} // ::1
	_ = binary.Write(msg, binary.BigEndian, octets)

	// new cookie
	rec = []uint16{5, 1}
	_ = binary.Write(msg, binary.BigEndian, rec)
	octets = []uint8{42}
	_ = binary.Write(msg, binary.BigEndian, octets)

	// end of message
	rec = []uint16{0, 0}
	rec[0] = setBit(rec[0], 15)
	_ = binary.Write(msg, binary.BigEndian, rec)

	fmt.Printf("gonna write: % x\n", msg)
	conn.Write(msg.Bytes())

	log.Println("server: conn: closed")
}
