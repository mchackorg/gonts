package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mchackorg/gonts/ntske"
)

var port string

func main() {
	flag.StringVar(&port, "port", "4430", "port")
	flag.Parse()

	service := "0.0.0.0:" + port

	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	certs, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{
		ServerName:   "localhost",
		NextProtos:   []string{"ntske/1"},
		Certificates: []tls.Certificate{certs},
	}

	listener, err := tls.Listen("tcp", service, config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")

	for {
		ke, err := ntske.NewConnection(listener)
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}

		go handleClient(ke)
	}
}

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}

func handleClient(ke *ntske.KeyExchange) {
	err := ke.Read()
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}
	// Check that we have complete data.

	ke.ExportKeys()

	fmt.Printf("Meta: %#v", ke.Meta)

	ke.StartMessage()
	ke.Algorithm()

	ke.Cookie([]uint8{42}, 1)

	ke.Write()

	// addr := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} // ::1
	// var addrs [][16]uint8
	// addrs[0] = addr
	// ke.NTPServer(addrs)

	log.Println("server: conn: closed")
}
