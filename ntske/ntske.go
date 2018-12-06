package ntske

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bifurcation/mint"
)

// KeyExchange is Network Time Security Key Exchange connection
type KeyExchange struct {
	hostport string
	conn     *mint.Conn
	reader   *bufio.Reader
	buf      *bytes.Buffer
	Meta     Data
}

type Data struct {
	C2s_key []byte
	S2c_key []byte
	Server  [][16]byte
	Cookie  [][]byte
	Algo    uint16 // AEAD
}

type Record struct {
	Type    uint16
	BodyLen uint16
}

const (
	rec_eom       = 0
	rec_nextproto = 1
	rec_aead      = 4
	rec_cookie    = 5
	rec_ntpserver = 6
)

func Connect(hostport string, config mint.Config) (*KeyExchange, error) {
	alpn := "ntske/1"
	config.NextProtos = []string{alpn}

	ke := new(KeyExchange)
	ke.hostport = hostport
	var err error

	ke.conn, err = mint.Dial("tcp", hostport, &config)
	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return nil, err
	}

	ke.reader = bufio.NewReader(ke.conn)

	state := ke.conn.ConnectionState()
	if state.NextProto != alpn {
		return nil, fmt.Errorf("server not speaking ntske/1")
	}

	return ke, nil
}

func (ke *KeyExchange) StartMessage() error {
	ke.buf = new(bytes.Buffer)

	var rec []uint16           // rectype, bodylen, body
	rec = []uint16{1, 2, 0x00} // NTPv4
	rec[0] = setBit(rec[0], 15)

	return binary.Write(ke.buf, binary.BigEndian, rec)
}

func (ke *KeyExchange) Server(addr [][16]uint8) error {
	var rec []uint16 // rectype, bodylen, body

	length := len(addr)
	rec = []uint16{6, uint16(length)} // 1 server addr == 16 bytes
	rec[0] = setBit(rec[0], 15)
	err := binary.Write(ke.buf, binary.BigEndian, rec)
	if err != nil {
		return err
	}

	//octets = []uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} // ::1
	for i := 0; i < length; i += 16 {
		err := binary.Write(ke.buf, binary.BigEndian, addr[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (ke *KeyExchange) Cookie(cookie []byte, cookielen int) error {
	var rec []uint16 // rectype, bodylen, body

	rec = []uint16{5, uint16(cookielen)}
	err := binary.Write(ke.buf, binary.BigEndian, rec)
	if err != nil {
		return err
	}

	return binary.Write(ke.buf, binary.BigEndian, cookie)
}

func (ke *KeyExchange) Algorithm() error {
	if ke.buf == nil {
		return fmt.Errorf("No buffer space - start with StartMessage()")
	}

	var rec []uint16 // rectype, bodylen, body

	// Server implementations of NTS extension fields for NTPv4 (Section 5)
	// MUST support AEAD_AES_SIV_CMAC_256 [RFC5297] (Numeric Identifier 15).
	rec = []uint16{4, 2, 0x0f} // AES-SIV-CMAC-256
	rec[0] = setBit(rec[0], 15)

	return binary.Write(ke.buf, binary.BigEndian, rec)
}

// Write() adds an End of Message record, then writes entire message to server
func (ke *KeyExchange) Write() error {
	if ke.buf == nil {
		return fmt.Errorf("No buffer space - start with StartMessage()")
	}

	rec := []uint16{0, 0}
	rec[0] = setBit(rec[0], 15)

	err := binary.Write(ke.buf, binary.BigEndian, rec)
	if err != nil {
		return err
	}

	_, err = ke.conn.Write(ke.buf.Bytes())
	return err
}

func (ke *KeyExchange) ExportKeys() error {
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
	binary.BigEndian.PutUint16(s2c_context, ke.Meta.Algo)
	s2c_context = append(s2c_context, 0x00)

	c2s_context := []byte("\x00\x00\x00")
	binary.BigEndian.PutUint16(c2s_context, ke.Meta.Algo)
	c2s_context = append(s2c_context, 0x01)

	var keylength = 32
	// Get exported keys
	var err error
	if ke.Meta.C2s_key, err = ke.conn.ComputeExporter(label, c2s_context, keylength); err != nil {
		return err
	}
	if ke.Meta.S2c_key, err = ke.conn.ComputeExporter(label, s2c_context, keylength); err != nil {
		return err
	}

	return nil
}

func (ke *KeyExchange) Read() error {
	var msg Record

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
		if hasBit(msg.Type, 15) {
			critical = true
		} else {
			critical = false
		}

		// Get rid of Critical bit.
		msg.Type &^= (1 << 15)
		fmt.Println("New message: ")
		fmt.Printf("  record type: % x\n", msg.Type)
		fmt.Printf("  body length: % x\n", msg.BodyLen)
		switch msg.Type {
		case rec_eom:
			fmt.Println("  Type: End of message")
			// Check that we have complete data. It's OK
			// if we don't fill in meta.Server --- this
			// means the client should use the same IP
			// address as the NTS-KE server.
			if len(ke.Meta.Cookie) == 0 || ke.Meta.Algo == 0 {
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
			ke.Meta.Algo = aead

		case rec_cookie:
			fmt.Println("  Type: Cookie")
			cookie := make([]byte, msg.BodyLen)
			err := binary.Read(ke.reader, binary.BigEndian, &cookie)
			if err != nil {
				return errors.New("buffer overrun")
			}
			fmt.Printf(" Cookie: % x\n", cookie)
			ke.Meta.Cookie = append(ke.Meta.Cookie, cookie)

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
				ke.Meta.Server = append(ke.Meta.Server, address)
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

			fmt.Printf("  Type: Unknown (% x)", msg.Type)
			fmt.Printf("  % x\n", unknownMsg)
		}
	}
}

func setBit(n uint16, pos uint) uint16 {
	n |= (1 << pos)
	return n
}

func hasBit(n uint16, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}
