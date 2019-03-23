package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/mchackorg/gonts/nts"
)

func main() {
	var xmitMsg nts.NTPHdr
	xmitMsg.SetMode(nts.Server)
	xmitMsg.SetVersion(4)
	//	xmitMsg.setLeap(LeapNotInSync)
	xmitMsg.Stratum = 1

	// Allocate a message to hold the response.
	var recvMsg nts.NTPHdr

	pc, err := net.ListenPacket("udp", "localhost:123")
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()

	recbuf := make([]byte, 1024)

	for {
		_, addr, err := pc.ReadFrom(recbuf)
		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}

		reader := bytes.NewReader(recbuf)

		xmitMsg.ReceiveTime = nts.ToNtpTime(time.Now())

		binary.Read(reader, binary.BigEndian, &recvMsg)
		fmt.Printf("recMsg %#v\n", recvMsg)

		xmitMsg.OriginTime = recvMsg.TransmitTime

		xmitMsg.TransmitTime = nts.ToNtpTime(time.Now())

		// Lie that we were just set.
		xmitMsg.ReferenceTime = xmitMsg.TransmitTime

		buf := new(bytes.Buffer)
		err = binary.Write(buf, binary.BigEndian, xmitMsg)
		if err != nil {
			log.Fatal("Couldn't binary write")
		}

		fmt.Printf("xmitMsg: %#v\n", xmitMsg)

		pc.WriteTo(buf.Bytes(), addr)
	}
}
