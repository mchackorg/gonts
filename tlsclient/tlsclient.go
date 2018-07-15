package main

// This began it's life as github.com/bifurcation/mint/bin/mint-client

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
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

func parseMsg(data []byte) (*Data, error) {
	var msg Msg

	meta := new(Data)
	buf := bytes.NewReader(data)

	for {
		err := binary.Read(buf, binary.BigEndian, &msg)
		if err != nil {
			fmt.Println("binary.Read failed:", err)
			return nil, err
		}

		// Get rid of Critical bit.
		msg.RecType &^= (1 << 15)
		fmt.Println("New message: ")
		fmt.Printf("  record type: % x\n", msg.RecType)
		fmt.Printf("  body length: % x\n", msg.BodyLen)
		switch msg.RecType {
		case rec_eom:
			fmt.Println("  Type: End of message")
			// Check that we have complete data. It's OK
			// if we don't fill in meta.Server --- this
			// means the client should use the same IP
			// address as the NTS-KE server.
			if len(meta.Cookie) == 0 || meta.Algo == 0 {
				return nil, errors.New("incomplete data")
			}

			return meta, nil
		case rec_nextproto:
			fmt.Println("  Type: Next proto")
			var nextProto uint16
			err := binary.Read(buf, binary.BigEndian, &nextProto)
			if err != nil {
				return nil, errors.New("buffer overrun")
			}
			fmt.Printf("next proto: % x\n", nextProto)

		case rec_aead:
			fmt.Println("  Type: AEAD")
			var aead uint16
			err := binary.Read(buf, binary.BigEndian, &aead)
			if err != nil {
				return nil, errors.New("buffer overrun")
			}
			fmt.Printf(" AEAD: % x\n", aead)
			meta.Algo = aead

		case rec_cookie:
			fmt.Println("  Type: Cookie")
			cookie := make([]byte, msg.BodyLen)
			err := binary.Read(buf, binary.BigEndian, &cookie)
			if err != nil {
				return nil, errors.New("buffer overrun")
			}
			fmt.Printf(" Cookie: % x\n", cookie)
			meta.Cookie = append(meta.Cookie, cookie)

		case rec_ntpserver:
			fmt.Println("  Type: NTP servers")

			var address [16]byte

			servers := msg.BodyLen / uint16(len(address))

			fmt.Printf(" number of servers: %d\n", servers)

			for i := 0; i < int(servers); i++ {
				err := binary.Read(buf, binary.BigEndian, &address)
				if err != nil {
					return nil, errors.New("buffer overrun")
				}
				fmt.Printf("  NTP server address: % x\n", address)
				meta.Server = append(meta.Server, address)
			}

		}
	}
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

	var response []byte
	buffer := make([]byte, 1024)
	var read int
	for err == nil {
		var r int
		r, err = conn.Read(buffer)
		read += r
		response = append(response, buffer...)
	}

	data, err := parseMsg(response)
	if err != nil {
		fmt.Printf("parseMsg error: %v\n", err)
		return
	}

	fmt.Printf("data: %v\n", data)

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
	binary.BigEndian.PutUint16(s2c_context, data.Algo)
	s2c_context = append(s2c_context, 0x00)

	c2s_context := []byte("\x00\x00\x00")
	binary.BigEndian.PutUint16(c2s_context, data.Algo)
	c2s_context = append(s2c_context, 0x01)

	var keylength = 32
	// exported keying materials
	if data.C2s_key, err = conn.ComputeExporter(label, c2s_context, keylength); err != nil {
		panic("bork")
	}
	if data.S2c_key, err = conn.ComputeExporter(label, s2c_context, keylength); err != nil {
		panic("bork")
	}

	b, err := json.Marshal(data)
	err = ioutil.WriteFile(datafn, b, 0644)
	fmt.Printf("Wrote %s\n", datafn)
}
