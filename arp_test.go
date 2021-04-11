package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// TestArpTable tests creation of arptable, addition, and removal of values.
func TestArpTable(t *testing.T) {
	arpTable := &ArpTable{}

	// generate test values
	// ArpEntry 1
	testIP := "127.0.0.1"
	testMAC := "ac:de:48:00:11:22"

	testMACHW, err := net.ParseMAC(testMAC)
	if err != nil {
		t.Fatalf("unable to parse MAC1: %v", err)
	}

	testARPEntry := &ArpEntry{
		IP:     net.ParseIP(testIP),
		Mac:    testMACHW,
		Status: StatusReady,
	}

	// ArpEntry 2
	testIP2 := "127.0.0.2"
	testMAC2 := "1e:77:9d:c0:09:c4"

	testMACHW2, err := net.ParseMAC(testMAC2)
	if err != nil {
		t.Fatalf("unable to parse MAC2, %v", err)
	}

	testARPEntry2 := &ArpEntry{
		IP:     net.ParseIP(testIP2),
		Mac:    testMACHW2,
		Status: StatusReady,
	}

	// Add ArpEntry 1
	err = arpTable.Add(testIP)
	if err != nil {
		t.Fatalf("unable to add testIP1: %v", err)
	}

	// Update ArpEntry 1 and and check it exists
	err = arpTable.Update(testIP, testMACHW)
	if err != nil {
		t.Fatalf("unable to add testIP2: %v", err)
	}

	entryResult, ok, err := arpTable.Get(testIP)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if !ok {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}

	if !compareArpEntry(entryResult, testARPEntry) {
		t.Fatalf("actual arp entry is not equal to expected ARP Entry")
	}

	// Update Arp Entry 2 and check 1 and 2 exist
	err = arpTable.Add(testIP2)
	if err != nil {
		t.Fatalf("unable to retrieve testIP2")
	}

	// Delete Arp Entry 1 and ensure that it was removed
	err = arpTable.Update(testIP2, testMACHW2)
	if err != nil {
		t.Fatalf("unable to update arp entry for testIP2: %v", err)
	}

	// Ensure both ArpEntry1 and ArpEntry2 are in the table
	entryResult, ok, err = arpTable.Get(testIP)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if !ok {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}

	if !compareArpEntry(entryResult, testARPEntry) {
		t.Fatalf("actual arp entry is not equal to expected ARP Entry")
	}

	entryResult, ok, err = arpTable.Get(testIP2)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if !ok {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}

	if !compareArpEntry(entryResult, testARPEntry2) {
		t.Fatalf("actual arp entry is not equal to expected ARP Entry")
	}

	// Remove ArpEntry 1 and ensure it's gone.
	err = arpTable.Remove(testIP)
	if err != nil {
		t.Fatalf("unable to remove testIP1: %v", err)
	}

	_, ok, err = arpTable.Get(testIP)
	if err != nil {
		t.Fatalf("unable to retrieve testIP1: %v", err)
	}
	if ok {
		t.Fatalf("ArpEntry 1 unexpectedly not removed")
	}

	// Remove ArpEntry 2 and ensure it's gone.
	err = arpTable.Remove(testIP2)
	if err != nil {
		t.Fatalf("unable to remove testIP2: %v", err)
	}

	_, ok, err = arpTable.Get(testIP2)
	if err != nil {
		t.Fatalf("unable to retrieve testIP2: %v", err)
	}

	if ok {
		t.Fatalf("ArpEntry2 unexpectedly not removed")
	}

}

func compareArpEntry(e1 *ArpEntry, e2 *ArpEntry) bool {
	// TODO: use go-cmp instead of deepequal
	if !reflect.DeepEqual(e1.IP, e2.IP) {
		return false
	}
	if !reflect.DeepEqual(e1.Mac.String(), e2.Mac.String()) {
		return false
	}

	if !reflect.DeepEqual(e1.Status, e2.Status) {
		return false
	}

	return true
}

// TestArpQueue tests the basic Add, Len, SendAndRemove functionality of ArpQueue.
func TestArpQueue_Add(t *testing.T) {
	length := uint(2)

	testBytes1, err := generateTestFrame(srcIP, testIP1)
	if err != nil {
		t.Fatalf("unable to generate testIP frame: %v", err)
	}
	testBytes2, err := generateTestFrame(srcIP, testIP2)
	if err != nil {
		t.Fatalf("unable to generate testIP frame: %v", err)
	}
	testBytes3, err := generateTestFrame(srcIP, testIP3)
	if err != nil {
		t.Fatalf("unable to generate testIP frame: %v", err)
	}

	queue := NewARPQueue(length)

	queue.Add(testIP1, testBytes1)
	if queue.Len() != 1 {
		t.Fatal("unexpected queue length")
	}

	queue.Add(testIP2, testBytes2)
	queue.Add(testIP3, testBytes3)

	// Check that queue has not overflowed limit
	if queue.Len() != 2 {
		t.Fatalf("unexpected queue length: %v", queue.Len())
	}

	// Confirm that value testIP1 no longer exists in the queue
	found := false
	e := queue.Front()
	for e != nil {
		entry, ok := e.Value.(*ArpQueueEntry)
		if !ok {
			t.Fatalf("invalid items in ArpQueue for IP: %v", entry.IP)
		}
		if entry.IP == testIP1 {
			found = true
		}
		e = e.Next()
	}

	if found {
		t.Fatalf("last added item unexpected not removed from queue: %v", testIP1)
	}
}

// TestArpQueue tests the basic SendAndRemove functionality of ArpQueue.
func TestArpQueue_Iterate(t *testing.T) {
	// generate test frame
	buff, err := generateTestFrame(testIP1, srcIP)
	if err != nil {
		t.Fatalf("unable to generate test frame: %v", buff)
	}

	// create ArpQueue and add
	queue := NewARPQueue(2)

	queue.Add(testIP1, buff)
	queue.Add(testIP1, buff)

	len := queue.Len()
	if len != 2 {
		t.Fatalf("unexpected buffer length: %v", len)
	}

	sentMessages := make(chan []byte, 10)
	fn := func(buff []byte) error {
		sentMessages <- buff
		return nil
	}

	queue.IterateAndRun(testIP1, fn)

	timer1 := time.NewTimer(5 * time.Second)

	count := 1
	for {
		select {
		case msg := <-sentMessages:
			if !reflect.DeepEqual(msg, buff) {
				t.Fatalf("unexpected received buffer: %v", msg)
			}
			if count == 2 {
				len = queue.Len()
				if len != 0 {
					t.Fatalf("unexpected queue length: %v", len)
				}
				return
			}
			count++
		case <-timer1.C:
			t.Fatal("test timed out without iterating through results")
		}
	}
}

var (
	srcIP         = "198.18.0.1"
	testIP1       = "198.18.0.5"
	testIP2       = "198.18.0.6"
	testIP3       = "198.18.0.7"
	etherTypeIPV4 = []byte("\x800")
)

const (
	// Version is protocol version
	Version = 4
	// HeaderLen is header length without extension headers
	HeaderLen = 20
)

const (
	MoreFragments HeaderFlags = 1 << iota // more fragments flag
	DontFragment                          // don't fragment flag
)

// IPv4Header struct used to create custom test header generator.
// This is based on the net.ipv4 package - but different in that marshalled format is BigEndian/wire format only.
// net.ipv4 package is using the raw socket format - with native Endian used for length fields.
type IPv4Header struct {
	Version  int         // protocol version
	Len      int         // header length
	TOS      int         // type-of-service
	TotalLen int         // packet total length
	ID       int         // identification
	Flags    HeaderFlags // flags
	FragOff  int         // fragment offset
	TTL      int         // time-to-live
	Protocol int         // next protocol
	Checksum int         // checksum
	Src      net.IP      // source address
	Dst      net.IP      // destination address
	Options  []byte      // options, extension headers
}

type HeaderFlags int

// Marshal generates byte slice from IPv4 header in the network byte order (Big Endian).
func (h *IPv4Header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, errors.New("nil header")
	}
	if h.Len < HeaderLen {
		return nil, errors.New("header too short")
	}
	hdrlen := HeaderLen + len(h.Options)
	b := make([]byte, hdrlen)
	b[0] = byte(Version<<4 | (hdrlen >> 2 & 0x0f))
	b[1] = byte(h.TOS)
	flagsAndFragOff := (h.FragOff & 0x1fff) | int(h.Flags<<13)
	binary.BigEndian.PutUint16(b[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndFragOff))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.ID))
	b[8] = byte(h.TTL)
	b[9] = byte(h.Protocol)
	binary.BigEndian.PutUint16(b[10:12], uint16(h.Checksum))
	if ip := h.Src.To4(); ip != nil {
		copy(b[12:16], ip[:net.IPv4len])
	}
	if ip := h.Dst.To4(); ip != nil {
		copy(b[16:20], ip[:net.IPv4len])
	} else {
		return nil, errors.New("address is missing")
	}
	if len(h.Options) > 0 {
		copy(b[HeaderLen:], h.Options)
	}
	return b, nil
}

// generateTestFrame returns marshalled byte slice in network byte order for testing.
func generateTestFrame(srcIP, dstIP string) ([]byte, error) {
	buff := make([]byte, 1518)
	hdr := IPv4Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      1,
		TotalLen: ipv4.HeaderLen, // Note in Go this is bytes but the wire format is Total >> 2 (i.e. 32 bit word number)
		ID:       0xcafe,
		Flags:    DontFragment,
		FragOff:  1500,
		TTL:      255,
		Protocol: 1,
		Checksum: 0xdead,
		Src:      net.ParseIP(srcIP),
		Dst:      net.ParseIP(dstIP),
	}
	packetBuff, err := hdr.Marshal()
	if err != nil {
		return nil, fmt.Errorf("unable to parse header: %v", err)
	}

	dstMAC := make([]byte, 6)
	srcMAC := make([]byte, 6) // TODO(sneha): change from hardcoded 0 values

	// add ethernet header
	copy(buff[0:6], dstMAC)
	copy(buff[6:12], srcMAC)
	copy(buff[12:14], etherTypeIPV4)
	copy(buff[14:14+hdr.Len], packetBuff)

	return buff[0 : 14+hdr.Len], nil
}
