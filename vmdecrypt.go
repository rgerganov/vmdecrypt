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

type Channel struct {
	lastRTPSeq  uint16
	firstPkt    bool
	pmtPid      uint16
	pmtPidFound bool
	ecmPid      uint16
	ecmPidFound bool
	masterKey   string
	aes_key_1   []byte
	aes_key_2   []byte
	mu          sync.Mutex
	buf         *ring.Ring
	c           *sync.Cond
	done        chan bool
}

type ChannelInfo struct {
	ch         *Channel
	numClients int
}

const RingSize = 64

var channelMapMu sync.Mutex
var channelMap map[string]*ChannelInfo

func newChannel(masterKey string) *Channel {
	ch := Channel{firstPkt: true, masterKey: masterKey}
	ch.buf = ring.New(RingSize)
	ch.c = sync.NewCond(&ch.mu)
	ch.done = make(chan bool)
	return &ch
}

func (ch *Channel) parseRTP(pkt []byte) []byte {
	version := pkt[0] >> 6
	if version != 2 {
		log.Fatal("Unexpected RTP version ", version)
	}
	hasExtension := (pkt[0] >> 4) & 1
	seq := binary.BigEndian.Uint16(pkt[2:4])
	if ch.firstPkt {
		ch.lastRTPSeq = seq - 1
		ch.firstPkt = false
	}
	if ch.lastRTPSeq+1 != seq {
		log.Fatal("RTP discontinuity detected")
	}
	ch.lastRTPSeq = seq
	extSize := 0
	if hasExtension > 0 {
		extSize = 4 + int(binary.BigEndian.Uint16(pkt[14:16])*4)
	}
	return pkt[12+extSize:]
}

func (ch *Channel) processECM(pkt []byte) {
	key, err := hex.DecodeString(ch.masterKey)
	if err != nil {
		log.Fatal(err)
	}
	cipher, _ := aes.NewCipher([]byte(key))
	ecm := make([]byte, 64)
	for i := 0; i < 4; i++ {
		cipher.Decrypt(ecm[i*16:], pkt[29+i*16:])
	}
	if ecm[0] != 0x43 || ecm[1] != 0x45 || ecm[2] != 0x42 {
		log.Fatal("Error decrypting ECM")
	}
	if pkt[5] == 0x81 {
		ch.aes_key_1 = ecm[9 : 9+16]
		ch.aes_key_2 = ecm[25 : 25+16]
	} else {
		ch.aes_key_2 = ecm[9 : 9+16]
		ch.aes_key_1 = ecm[25 : 25+16]
	}
}

func (ch *Channel) decodePacket(pkt []byte) {
	if ch.aes_key_1 == nil || ch.aes_key_2 == nil {
		return
	}
	scramble := (pkt[3] >> 6) & 3
	if scramble < 2 {
		return
	}
	var aes_key []byte
	if scramble == 2 {
		aes_key = ch.aes_key_2
	} else if scramble == 3 {
		aes_key = ch.aes_key_1
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

func (ch *Channel) processPacket(pkt []byte) {
	if pkt[0] != 0x47 {
		log.Fatal("Expected sync byte")
	}
	pid := binary.BigEndian.Uint16(pkt[1:3]) & 0x1fff
	if !ch.pmtPidFound && pid == 0 {
		// process PAT
		if pkt[4] != 0 {
			log.Fatal("Pointer fields are not supported yet")
		}
		if pkt[5] != 0 {
			log.Fatal("Unexpected PAT table ID", pkt[5])
		}
		ch.pmtPid = binary.BigEndian.Uint16(pkt[15:17]) & 0x1fff
		ch.pmtPidFound = true
		log.Printf("PMT pid=0x%x", ch.pmtPid)
	}
	if !ch.ecmPidFound && ch.pmtPidFound && pid == ch.pmtPid {
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
		ch.ecmPid = binary.BigEndian.Uint16(pkt[21:23])
		ch.ecmPidFound = true
		log.Printf("ECM pid=0x%x", ch.ecmPid)
	}
	if ch.ecmPidFound && pid == ch.ecmPid {
		ch.processECM(pkt)
	}
	ch.decodePacket(pkt)

	ch.mu.Lock()
	ch.buf.Value = pkt
	ch.buf = ch.buf.Next()
	ch.c.Broadcast()
	ch.mu.Unlock()
	//savePacket(pkt)
	//log.Printf("% x\n", pkt)
}

func (ch *Channel) parsePayload(pkt []byte) {
	if len(pkt)%188 != 0 {
		log.Fatal("Unexpected length")
	}
	for len(pkt) > 0 {
		ch.processPacket(pkt[:188])
		pkt = pkt[188:]
	}
}

func (ch *Channel) currentPtr() *ring.Ring {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.buf
}

func (ch *Channel) nextPtr(ptr *ring.Ring) (*ring.Ring, interface{}) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	for ptr == ch.buf {
		ch.c.Wait()
	}
	return ptr.Next(), ptr.Value
}

func vmdecrypt(ch *Channel) {
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

	log.Println("Start decrypting channel ...")
loop:
	for {
		select {
		case <-ch.done:
			break loop
		default:
			// do nothing
		}
		pkt := make([]byte, 1500)
		n, _, _, err := p.ReadFrom(pkt)
		if err != nil {
			log.Fatal(err)
		}
		payload := ch.parseRTP(pkt[:n])
		ch.parsePayload(payload)
	}
	log.Println("Stopped decrypting channel")
	p.LeaveGroup(eth1, &net.UDPAddr{IP: group})
	ch.done <- true
	//log.Println(n, "bytes read from", src)
	//log.Printf("% x", b[:n])
}

func httpHandler(w http.ResponseWriter, req *http.Request) {
	channelMapMu.Lock()
	chInfo, ok := channelMap["btv"]
	if !ok {
		ch := newChannel("48a028403963ae6bb8a26ec85677567e")
		chInfo = &ChannelInfo{ch: ch, numClients: 1}
		channelMap["btv"] = chInfo
		go vmdecrypt(ch)
	} else {
		chInfo.numClients += 1
	}
	channelMapMu.Unlock()

	ch := chInfo.ch
	log.Println("Start serving client")
	ptr := ch.currentPtr()
	var val interface{}
	for {
		ptr, val = ch.nextPtr(ptr)
		_, err := w.Write(val.([]byte))
		if err != nil {
			break
		}
	}

	log.Println("Stop serving client")
	channelMapMu.Lock()
	chInfo, ok = channelMap["btv"]
	if ok {
		chInfo.numClients -= 1
		if chInfo.numClients == 0 {
			chInfo.ch.done <- true
			<-chInfo.ch.done
			delete(channelMap, "btv")
		}
	}
	channelMapMu.Unlock()
}

func main() {
	channelMap = make(map[string]*ChannelInfo)
	http.HandleFunc("/", httpHandler)
	log.Fatal(http.ListenAndServe(":8090", nil))
}
