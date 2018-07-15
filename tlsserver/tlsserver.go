package main

// This began it's life as github.com/bifurcation/mint/bin/mint-server

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
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
	// TODO The cookie(s?) to be delivered to the NTS client (*and* to the NTP
	// server below) are to be baked according to some good recipe, perhaps: 7.
	// Suggested Format for NTS Cookies
	cookie := [5]uint8{42, 47, 11, 40, 96}
	rec = []uint16{5, uint16(len(cookie))}
	_ = binary.Write(msg, binary.BigEndian, rec)
	_ = binary.Write(msg, binary.BigEndian, cookie)

	// end of message
	rec = []uint16{0, 0}
	rec[0] = setBit(rec[0], 15)
	_ = binary.Write(msg, binary.BigEndian, rec)

	fmt.Printf("gonna write: % x\n", msg)
	conn.Write(msg.Bytes())

	log.Println("delivering cookie to NTP *server*")
	conn, err := net.Dial("tcp", "localhost:6000")
	if err != nil {
		fmt.Printf("dial failed: %s\n", err)
	} else {
		encoder := json.NewEncoder(conn)
		if err = encoder.Encode(cookie); err != nil {
			fmt.Printf("encode failed: %s\n", err)
		}
	}

	log.Println("server: conn: closed")
}
