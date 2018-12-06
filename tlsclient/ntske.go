package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bifurcation/mint"
)

type KeyExchange struct {
	hostport string
	conn     *mint.Conn
	reader   *bufio.Reader
	meta     Data
}

func Connect(hostport string, config mint.Config) (*KeyExchange, error) {
	ke := new(KeyExchange)
	ke.hostport = hostport
	var err error

	ke.conn, err = mint.Dial("tcp", addr, &config)
	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return nil, err
	}

	ke.reader = bufio.NewReader(ke.conn)

	state := ke.conn.ConnectionState()
	if state.NextProto != "ntske/1" {
		return nil, fmt.Errorf("server not speaking ntske/1")
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

	fmt.Printf("writing:\n% x\n", msg)
	ke.conn.Write(msg.Bytes())

	return ke, nil
}

func (ke *KeyExchange) readReply() error {
	var msg Msg
	var critical bool

	for {
		err := binary.Read(ke.reader, binary.BigEndian, &msg)
		if err != nil {
			fmt.Println("binary.Read failed:", err)
			return err
		}

		// C (Critical Bit): Determines the disposition of
		// unrecognized Record Types. Implementations which
		// receive a record with an unrecognized Record Type
		// MUST ignore the record if the Critical Bit is 0 and
		// MUST treat it as an error if the Critical Bit is 1.
		if hasBit(msg.RecType, 15) {
			critical = true
		} else {
			critical = false
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
			if len(ke.meta.Cookie) == 0 || ke.meta.Algo == 0 {
				return errors.New("incomplete data")
			}

			return nil

		case rec_nextproto:
			fmt.Println("  Type: Next proto")
			var nextProto uint16
			err := binary.Read(ke.reader, binary.BigEndian, &nextProto)
			if err != nil {
				return errors.New("buffer overrun")
			}
			fmt.Printf("next proto: % x\n", nextProto)

		case rec_aead:
			fmt.Println("  Type: AEAD")
			var aead uint16
			err := binary.Read(ke.reader, binary.BigEndian, &aead)
			if err != nil {
				return errors.New("buffer overrun")
			}
			fmt.Printf(" AEAD: % x\n", aead)
			ke.meta.Algo = aead

		case rec_cookie:
			fmt.Println("  Type: Cookie")
			cookie := make([]byte, msg.BodyLen)
			err := binary.Read(ke.reader, binary.BigEndian, &cookie)
			if err != nil {
				return errors.New("buffer overrun")
			}
			fmt.Printf(" Cookie: % x\n", cookie)
			ke.meta.Cookie = append(ke.meta.Cookie, cookie)

		case rec_ntpserver:
			fmt.Println("  Type: NTP servers")

			var address [16]byte

			servers := msg.BodyLen / uint16(len(address))

			fmt.Printf(" number of servers: %d\n", servers)

			for i := 0; i < int(servers); i++ {
				err := binary.Read(ke.reader, binary.BigEndian, &address)
				if err != nil {
					return errors.New("buffer overrun")
				}
				fmt.Printf("  NTP server address: % x\n", address)
				ke.meta.Server = append(ke.meta.Server, address)
			}

		default:
			if critical {
				return errors.New("unknown record type with critical bit set")
			}

			// Swallow unknown record.
			unknownMsg := make([]byte, msg.BodyLen)
			err := binary.Read(ke.reader, binary.BigEndian, &unknownMsg)
			if err != nil {
				return errors.New("buffer overrun")
			}

			fmt.Printf("  Type: Unknown (% x)", msg.RecType)
			fmt.Printf("  % x\n", unknownMsg)
		}
	}
}
