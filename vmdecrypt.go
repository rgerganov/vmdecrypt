package main

import (
	"container/ring"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
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
	ioerr       bool
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

func (ch *Channel) parseRTP(pkt []byte) ([]byte, error) {
	version := pkt[0] >> 6
	if version != 2 {
		return nil, fmt.Errorf("Unexpected RTP version %v", version)
	}
	hasExtension := (pkt[0] >> 4) & 1
	seq := binary.BigEndian.Uint16(pkt[2:4])
	if ch.firstPkt {
		ch.lastRTPSeq = seq - 1
		ch.firstPkt = false
	}
	if ch.lastRTPSeq+1 != seq {
		log.Println("RTP discontinuity detected")
	}
	ch.lastRTPSeq = seq
	extSize := 0
	if hasExtension > 0 {
		extSize = 4 + int(binary.BigEndian.Uint16(pkt[14:16])*4)
	}
	return pkt[12+extSize:], nil
}

func (ch *Channel) processECM(pkt []byte) error {
	key, _ := hex.DecodeString(ch.masterKey)
	cipher, _ := aes.NewCipher([]byte(key))
	ecm := make([]byte, 64)
	for i := 0; i < 4; i++ {
		cipher.Decrypt(ecm[i*16:], pkt[29+i*16:])
	}
	if ecm[0] != 0x43 || ecm[1] != 0x45 || ecm[2] != 0x42 {
		return errors.New("Error decrypting ECM")
	}
	if pkt[5] == 0x81 {
		ch.aes_key_1 = ecm[9 : 9+16]
		ch.aes_key_2 = ecm[25 : 25+16]
	} else {
		ch.aes_key_2 = ecm[9 : 9+16]
		ch.aes_key_1 = ecm[25 : 25+16]
	}
	return nil
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

func (ch *Channel) parseEcmPid(desc []byte) error {
	//log.Printf("% x\n", desc)
	for len(desc) > 0 {
		tag := desc[0]
		length := desc[1]
		if tag == 0x09 {
			caid := binary.BigEndian.Uint16(desc[2:4])
			if caid == 0x5601 {
				ch.ecmPid = binary.BigEndian.Uint16(desc[4:6])
				ch.ecmPidFound = true
				//log.Printf("ECM pid=0x%x", ch.ecmPid)
				return nil
			}
		}
		desc = desc[2+length:]
	}
	return errors.New("Cannot find ECM PID")
}

func (ch *Channel) processPacket(pkt []byte) error {
	if pkt[0] != 0x47 {
		return fmt.Errorf("Expected sync byte but got: %v", pkt[0])
	}
	pid := binary.BigEndian.Uint16(pkt[1:3]) & 0x1fff
	if !ch.pmtPidFound && pid == 0 {
		// process PAT
		if pkt[4] != 0 {
			return errors.New("[PAT] Pointer fields are not supported yet")
		}
		if pkt[5] != 0 {
			return fmt.Errorf("Unexpected PAT table ID: %v", pkt[5])
		}
		ch.pmtPid = binary.BigEndian.Uint16(pkt[15:17]) & 0x1fff
		ch.pmtPidFound = true
		//log.Printf("PMT pid=0x%x", ch.pmtPid)
	}
	if !ch.ecmPidFound && ch.pmtPidFound && pid == ch.pmtPid {
		// process PMT
		if pkt[4] != 0 {
			return errors.New("[PMT] Pointer fields are not supported yet")
		}
		if pkt[5] != 2 {
			return fmt.Errorf("Unexpected PMT table ID: %v", pkt[5])
		}
		piLength := binary.BigEndian.Uint16(pkt[15:17]) & 0x03ff
		if err := ch.parseEcmPid(pkt[17 : 17+piLength]); err != nil {
			return err
		}
	}
	if ch.ecmPidFound && pid == ch.ecmPid {
		if err := ch.processECM(pkt); err != nil {
			return err
		}
	}
	ch.decodePacket(pkt)
	ch.addToBuf(pkt)
	return nil
	//savePacket(pkt)
	//log.Printf("% x\n", pkt)
}

func (ch *Channel) parseRTPPayload(pkt []byte) error {
	if len(pkt)%188 != 0 {
		return fmt.Errorf("Unexpected RTP payload length: %v", len(pkt))
	}
	for len(pkt) > 0 {
		if err := ch.processPacket(pkt[:188]); err != nil {
			return err
		}
		pkt = pkt[188:]
	}
	return nil
}

func (ch *Channel) addToBuf(val interface{}) {
	ch.mu.Lock()
	ch.buf.Value = val
	ch.buf = ch.buf.Next()
	ch.c.Broadcast()
	ch.mu.Unlock()
}

func (ch *Channel) currentPtr() *ring.Ring {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.buf
}

func (ch *Channel) nextPtr(ptr *ring.Ring) (*ring.Ring, interface{}) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	for ptr == ch.buf && !ch.ioerr {
		ch.c.Wait()
	}
	if !ch.ioerr {
		return ptr.Next(), ptr.Value
	} else {
		return ptr, nil
	}
}

func (ch *Channel) closeBuf() {
	ch.mu.Lock()
	ch.ioerr = true
	ch.c.Broadcast()
	ch.mu.Unlock()
}

func vmdecrypt(ch *Channel, hostPort string) {
	eth1, err := net.InterfaceByName("eth1")
	if err != nil {
		log.Fatal(err)
	}

	host, _, _ := net.SplitHostPort(hostPort)
	group := net.ParseIP(host)
	c, err := net.ListenPacket("udp4", hostPort)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(eth1, &net.UDPAddr{IP: group}); err != nil {
		log.Println(err)
		goto ioerr
	}
	defer p.LeaveGroup(eth1, &net.UDPAddr{IP: group})

	log.Println("Start decrypting channel @", hostPort)
	for {
		select {
		case <-ch.done:
			goto noclients
		default:
			// do nothing
		}
		pkt := make([]byte, 1500)
		p.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, _, err := p.ReadFrom(pkt)
		if err != nil {
			log.Printf("%v @ %v", err, hostPort)
			goto ioerr
		}
		payload, err := ch.parseRTP(pkt[:n])
		if err != nil {
			log.Printf("%v @ %v", err, hostPort)
			goto ioerr
		}
		if err := ch.parseRTPPayload(payload); err != nil {
			log.Printf("%v @ %v", err, hostPort)
			goto ioerr
		}
	}
noclients:
	log.Println("No more clients, stop decrypting channel @", hostPort)
	ch.done <- true
	log.Println("Done @", hostPort)
	return

ioerr:
	log.Println("I/O error, stop decrypting channel @", hostPort)
	ch.closeBuf()
	<-ch.done
	ch.done <- true
	log.Println("Done @", hostPort)
}

func httpHandler(w http.ResponseWriter, req *http.Request) {
	// requestURI should be /rtp/236.5.22.49:15072/48a028403963ae6bb8a26ec85677567e
	parts := strings.Split(req.RequestURI[5:], "/")
	if len(parts) != 2 {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	hostPort := parts[0]
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	masterKey := parts[1]
	if _, err := hex.DecodeString(masterKey); err != nil || len(masterKey) != 32 {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	channelMapMu.Lock()
	chInfo, ok := channelMap[hostPort]
	if !ok {
		ch := newChannel(masterKey)
		chInfo = &ChannelInfo{ch: ch, numClients: 1}
		channelMap[hostPort] = chInfo
		go vmdecrypt(ch, hostPort)
	} else {
		chInfo.numClients += 1
	}
	channelMapMu.Unlock()

	ch := chInfo.ch
	log.Println("Start serving client", req.RemoteAddr)
	ptr := ch.currentPtr()
	var val interface{}
	for {
		ptr, val = ch.nextPtr(ptr)
		if val == nil {
			break
		}
		_, err := w.Write(val.([]byte))
		if err != nil {
			break
		}
	}

	log.Println("Stop serving client", req.RemoteAddr)
	channelMapMu.Lock()
	chInfo, ok = channelMap[hostPort]
	if ok {
		chInfo.numClients -= 1
		if chInfo.numClients == 0 {
			chInfo.ch.done <- true
			<-chInfo.ch.done
			delete(channelMap, hostPort)
		}
	}
	channelMapMu.Unlock()
}

func main() {
	channelMap = make(map[string]*ChannelInfo)
	http.HandleFunc("/rtp/", httpHandler)
	log.Fatal(http.ListenAndServe(":8090", nil))
}
