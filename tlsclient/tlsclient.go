package main

// This began it's life as github.com/bifurcation/mint/bin/mint-client

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/bifurcation/mint"
)

var addr string
var dtls bool
var dontValidate bool

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}

// type nextproto_ntske struct {
// 	Rectype uint16
// 	Bodylen uint16
// 	Body    []uint16
// }

// func nextprotoRec() *nextproto_ntske {
// 	rec := new(nextproto_ntske)
// 	rec.Rectype = 1
// 	rec.Rectype = setBit(rec.Rectype, 15)
// 	rec.Body = []uint16{0}
// 	rec.Bodylen = 2
// 	return rec
// }

// type aead_ntske struct {
// 	Rectype uint16
// 	Bodylen uint16
// 	Body    []uint16
// }

// func aeadRec() *aead_ntske {
// 	rec := new(aead_ntske)
// 	rec.Rectype = 4
// 	rec.Rectype = setBit(rec.Rectype, 15)
// 	rec.Body = []uint16{15}
// 	rec.Bodylen = 2
// 	return rec
// }

// type server_ntske struct {
// 	Rectype uint16
// 	Bodylen uint16
// 	Body    [][16]byte
// }

// func serverRec() *server_ntske {
// 	rec := new(server_ntske)
// 	rec.Rectype = 6
// 	rec.Rectype = setBit(rec.Rectype, 15)
// 	rec.Body = [][16]byte{{1}}
// 	rec.Bodylen = 2
// 	return rec
// }

// type end_ntske struct {
// 	Rectype uint16
// 	Bodylen uint16
// }

// func endRec() *end_ntske {
// 	rec := new(end_ntske)
// 	rec.Rectype = 0
// 	rec.Rectype = setBit(rec.Rectype, 15)
// 	rec.Bodylen = 0
// 	return rec
// }

// type cookie_ntske struct {
// 	Rectype uint16
// 	Bodylen uint16
// 	Body    []uint32
// }

// func cookieRec() *cookie_ntske {
// 	rec := new(cookie_ntske)
// 	rec.Rectype = 5
// 	rec.Body = []uint32{4711}
// 	rec.Bodylen = 4
// 	return rec
// }

type Data struct {
	C2s_key []byte
	S2c_key []byte
	Server  string
	Cookie  []byte
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

	msg := new(bytes.Buffer)

	var rec []uint16 // rectype, bodylen, body
	// nextproto
	rec = []uint16{1, 2, 0x00} // NTPv4
	rec[0] = setBit(rec[0], 15)
	err = binary.Write(msg, binary.BigEndian, rec)

	// AEAD
	rec = []uint16{4, 2, 0x0f} // AES-SIV-CMAC-256
	rec[0] = setBit(rec[0], 15)
	err = binary.Write(msg, binary.BigEndian, rec)

	// end of message
	rec = []uint16{0, 0}
	rec[0] = setBit(rec[0], 15)
	err = binary.Write(msg, binary.BigEndian, rec)

	fmt.Printf("gonna write:\n% x\n", msg)
	conn.Write(msg.Bytes())

	response := ""
	buffer := make([]byte, 1024)
	var read int
	for err == nil {
		var r int
		r, err = conn.Read(buffer)
		read += r
		response += string(buffer)
	}

	// fmt.Printf("got:\n")
	// for i := 0; i < read; i++ {
	// 	fmt.Printf("%02x ", response[i])
	// 	if (i+1)%16 == 0 {
	// 		fmt.Printf("\n")
	// 	}
	// }
	// fmt.Printf("\n")

	data := new(Data)
	// TODO
	// when parsed: stuff ntp server(s) and cookie(s) into data

	// 4.2. in https://tools.ietf.org/html/draft-dansarie-nts-00
	label := "EXPORTER-network-time-security/1"
	// 0x0000 = nextproto (protocol ID for NTPv4)
	// 0x000f = AEAD (AES-SIV-CMAC-256)
	// 0x00 s2c | 0x01 c2s
	s2c_context := []byte("\x00\x00\x00\x0f\x00")
	c2s_context := []byte("\x00\x00\x00\x0f\x01")

	var keylength = 32
	// exported keying materials
	if data.C2s_key, err = conn.ComputeExporter(label, c2s_context, keylength); err != nil {
		panic("bork")
	}
	if data.S2c_key, err = conn.ComputeExporter(label, s2c_context, keylength); err != nil {
		panic("bork")
	}

	b, err := json.Marshal(data)
	fmt.Printf("%s\n", b)
}
