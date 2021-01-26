package main

import (
	"container/ring"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

var lastRTPSeq uint16 = 0
var firstPkt = true
var pmtPid uint16
var pmtPidFound = false
var ecmPid uint16
var ecmPidFound = false
var masterKey = "09ce6d566f42302278a4b8121d6a4c74"
var aes_key_1 []byte
var aes_key_2 []byte

var mu sync.Mutex
var buf = ring.New(50)
var c = sync.NewCond(&mu)

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

func processECM(pkt []byte) {
	key, err := hex.DecodeString(masterKey)
	if err != nil {
		log.Fatal(err)
	}
	//log.Printf("% x", key)
	cipher, _ := aes.NewCipher([]byte(key))
	ecm := make([]byte, 64)
	for i := 0; i < 4; i++ {
		cipher.Decrypt(ecm[i*16:], pkt[29+i*16:])
	}
	if ecm[0] != 0x43 || ecm[1] != 0x45 || ecm[2] != 0x42 {
		log.Fatal("Error decrypting ECM")
	}
	if pkt[5] == 0x81 {
		aes_key_1 = ecm[9 : 9+16]
		aes_key_2 = ecm[25 : 25+16]
	} else {
		aes_key_2 = ecm[9 : 9+16]
		aes_key_1 = ecm[25 : 25+16]
	}
}

func decodePacket(pkt []byte) {
	if aes_key_1 == nil || aes_key_2 == nil {
		return
	}
	scramble := (pkt[3] >> 6) & 3
	if scramble < 2 {
		return
	}
	var aes_key []byte
	if scramble == 2 {
		aes_key = aes_key_2
	} else if scramble == 3 {
		aes_key = aes_key_1
	}
	cipher, _ := aes.NewCipher([]byte(aes_key))
	pkt = pkt[4:]
	for len(pkt) > 16 {
		cipher.Decrypt(pkt, pkt)
		pkt = pkt[16:]
	}
}

func savePacket(pkt []byte) {
	f, err := os.OpenFile("dump.ts", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.Write(pkt); err != nil {
		log.Fatal(err)
	}
}

func processPacket(pkt []byte) {
	if pkt[0] != 0x47 {
		log.Fatal("Expected sync byte")
	}
	pid := binary.BigEndian.Uint16(pkt[1:3]) & 0x1fff
	if !pmtPidFound && pid == 0 {
		// process PAT
		if pkt[4] != 0 {
			log.Fatal("Pointer fields are not supported yet")
		}
		if pkt[5] != 0 {
			log.Fatal("Unexpected PAT table ID", pkt[5])
		}
		pmtPid = binary.BigEndian.Uint16(pkt[15:17]) & 0x1fff
		pmtPidFound = true
		log.Printf("PMT pid=0x%x", pmtPid)
	}
	if !ecmPidFound && pmtPidFound && pid == pmtPid {
		// process PMT
		if pkt[4] != 0 {
			log.Fatal("Pointer fields are not supported yet")
		}
		if pkt[5] != 2 {
			log.Fatal("Unexpected PMT table ID", pkt[5])
		}
		if pkt[16] != 6 {
			log.Fatal("Unexpected program info length", pkt[16])
		}
		caid := binary.BigEndian.Uint16(pkt[19:21])
		if caid != 0x5601 {
			log.Fatal("Unexpected CAID", caid)
		}
		ecmPid = binary.BigEndian.Uint16(pkt[21:23])
		ecmPidFound = true
		log.Printf("ECM pid=0x%x", ecmPid)
	}
	if ecmPidFound && pid == ecmPid {
		processECM(pkt)
	}
	decodePacket(pkt)

	mu.Lock()
	buf.Value = pkt
	buf = buf.Next()
	c.Broadcast()
	mu.Unlock()
	//savePacket(pkt)
	//log.Printf("% x\n", pkt)
}

func parsePayload(pkt []byte) {
	if len(pkt)%188 != 0 {
		log.Fatal("Unexpected length")
	}
	for len(pkt) > 0 {
		processPacket(pkt[:188])
		pkt = pkt[188:]
	}
}

func vmdecrypt() {
	eth1, err := net.InterfaceByName("eth1")
	if err != nil {
		log.Fatal(err)
	}

	group := net.IPv4(236, 5, 22, 49)
	c, err := net.ListenPacket("udp4", "0.0.0.0:15072")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(eth1, &net.UDPAddr{IP: group}); err != nil {
		log.Fatal(err)
	}

	for {
		pkt := make([]byte, 1500)
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

func httpHandler(w http.ResponseWriter, req *http.Request) {
	mu.Lock()
	ptr := buf
	mu.Unlock()

	log.Println("Serving client ...")
	for {
		mu.Lock()
		for ptr == buf {
			c.Wait()
		}
		val := ptr.Value
		ptr = ptr.Next()
		mu.Unlock()
		w.Write(val.([]byte))
	}
}

func main() {
	go vmdecrypt()
	http.HandleFunc("/", httpHandler)
	log.Fatal(http.ListenAndServe(":8090", nil))
}
