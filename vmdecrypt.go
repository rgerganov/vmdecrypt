package main

import (
	"encoding/binary"
	"golang.org/x/net/ipv4"
	"log"
	"net"
)

const (
	srvAddr         = "236.5.19.10:11480"
	maxDatagramSize = 1024
)

var lastRTPSeq uint16 = 0
var firstPkt = true

func parseRTP(pkt []byte) []byte {
	version := pkt[0] >> 6
	if version != 2 {
		log.Fatal("Unexpected RTP version ", version)
	}
	hasExtension := (pkt[0] >> 4) & 1
	seq := binary.BigEndian.Uint16(pkt[2:4])
	//ts := binary.BigEndian.Uint32(pkt[4:8])
	//log.Println(seq)
	if firstPkt {
		lastRTPSeq = seq - 1
		firstPkt = false
	}
	if lastRTPSeq+1 != seq {
		log.Fatal("RTP discontinuity detected")
	}
	lastRTPSeq = seq
	extSize := 0
	if hasExtension > 0 {
		extSize = 4 + int(binary.BigEndian.Uint16(pkt[14:16])*4)
	}
	return pkt[12+extSize:]
}

func parsePayload(pkt []byte) {
	if pkt[0] != 0x47 {
		log.Fatal("Expected sync byte")
	}
	//log.Println(len(pkt))
	if len(pkt)%188 != 0 {
		log.Fatal("Unexpected length")
	}
}

func main() {
	eth1, err := net.InterfaceByName("eth1")
	if err != nil {
		log.Fatal(err)
	}

	group := net.IPv4(236, 5, 19, 10)
	c, err := net.ListenPacket("udp4", "0.0.0.0:11480")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(eth1, &net.UDPAddr{IP: group}); err != nil {
		log.Fatal(err)
	}

	pkt := make([]byte, 1500)

	for {
		n, _, _, err := p.ReadFrom(pkt)
		if err != nil {
			log.Fatal(err)
		}
		payload := parseRTP(pkt[:n])
		parsePayload(payload)
	}
	//log.Println(n, "bytes read from", src)
	//log.Printf("% x", b[:n])
}
