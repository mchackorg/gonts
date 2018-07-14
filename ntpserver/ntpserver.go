package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

// The LeapIndicator is used to warn if a leap second should be inserted
// or deleted in the last minute of the current month.
type LeapIndicator uint8

// An ntpTime is a 64-bit fixed-point (Q32.32) representation of the number of
// seconds elapsed.
type ntpTime uint64

// An ntpTimeShort is a 32-bit fixed-point (Q16.16) representation of the
// number of seconds elapsed.
type ntpTimeShort uint32

// msg is an internal representation of an NTP packet.
type msg struct {
	LiVnMode       uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      ntpTimeShort
	RootDispersion ntpTimeShort
	ReferenceID    uint32
	ReferenceTime  ntpTime
	OriginTime     ntpTime
	ReceiveTime    ntpTime
	TransmitTime   ntpTime
}

type mode uint8

// NTP modes. This package uses only client mode.
const (
	reserved mode = 0 + iota
	symmetricActive
	symmetricPassive
	client
	server
	broadcast
	controlMessage
	reservedPrivate
)

// setVersion sets the NTP protocol version on the message.
func (m *msg) setVersion(v int) {
	m.LiVnMode = (m.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the message.
func (m *msg) setMode(md mode) {
	m.LiVnMode = (m.LiVnMode & 0xf8) | uint8(md)
}

// setLeap modifies the leap indicator on the message.
func (m *msg) setLeap(li LeapIndicator) {
	m.LiVnMode = (m.LiVnMode & 0x3f) | uint8(li)<<6
}

// getVersion returns the version value in the message.
func (m *msg) getVersion() int {
	return int((m.LiVnMode >> 3) & 0x07)
}

// getMode returns the mode value in the message.
func (m *msg) getMode() mode {
	return mode(m.LiVnMode & 0x07)
}

// getLeap returns the leap indicator on the message.
func (m *msg) getLeap() LeapIndicator {
	return LeapIndicator((m.LiVnMode >> 6) & 0x03)
}

const (
	// LeapNoWarning indicates no impending leap second.
	LeapNoWarning LeapIndicator = 0

	// LeapAddSecond indicates the last minute of the day has 61 seconds.
	LeapAddSecond = 1

	// LeapDelSecond indicates the last minute of the day has 59 seconds.
	LeapDelSecond = 2

	// LeapNotInSync indicates an unsynchronized leap second.
	LeapNotInSync = 3
)

// Internal variables
var (
	ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Internal constants
const (
	defaultNtpVersion = 4
	nanoPerSec        = 1000000000
	maxStratum        = 16
	defaultTimeout    = 5 * time.Second
	maxPollInterval   = (1 << 17) * time.Second
	maxDispersion     = 16 * time.Second
)

// toNtpTime converts the time.Time value t into its 64-bit fixed-point
// ntpTime representation.
func toNtpTime(t time.Time) ntpTime {
	nsec := uint64(t.Sub(ntpEpoch))
	sec := nsec / nanoPerSec
	// Round up the fractional component so that repeated conversions
	// between time.Time and ntpTime do not yield continually decreasing
	// results.
	frac := (((nsec - sec*nanoPerSec) << 32) + nanoPerSec - 1) / nanoPerSec
	return ntpTime(sec<<32 | frac)
}

func main() {
	xmitMsg := new(msg)
	xmitMsg.setMode(server)
	xmitMsg.setVersion(4)
	//	xmitMsg.setLeap(LeapNotInSync)
	xmitMsg.Stratum = 1

	// Allocate a message to hold the response.
	recvMsg := new(msg)

	pc, err := net.ListenPacket("udp", "localhost:123")
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()

	recbuf := make([]byte, 1024)

	for {
		_, addr, err := pc.ReadFrom(recbuf)
		fmt.Printf("Received data from %v: %v\n", addr, recbuf)
		if err != nil {
			fmt.Println("Error: ", err)
		}

		binary.Read(bytes.NewReader(recbuf), binary.BigEndian, recvMsg)
		fmt.Printf("recMsg %v\n", recvMsg)

		xmitMsg.OriginTime = recvMsg.TransmitTime

		xmitMsg.ReferenceTime = toNtpTime(time.Now())
		xmitMsg.TransmitTime = xmitMsg.ReferenceTime

		buf := new(bytes.Buffer)
		err = binary.Write(buf, binary.BigEndian, xmitMsg)
		if err != nil {
			log.Fatal("Couldn't binary write")
		}

		fmt.Printf("xmitMsg: %v\n", xmitMsg)

		pc.WriteTo(buf.Bytes(), addr)
	}
}
