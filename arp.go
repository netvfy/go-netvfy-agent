package agent

import (
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Common constants used to craft ARP requests and replies.
const (
	// TypeARP header value used for EtherType.
	TypeARP uint16 = 0x0806
	// TypeIPv4 header value used for either EtherType or ProtocolType.
	TypeIPv4 uint16 = 0x0800
	// HTypeEthernet is the hardware ethernet header value
	HTypeEthernet uint16 = 1
	// HLenEthernet is the hardware length for type ethernet - 6.
	HLenEthernet = 6
	// PLenIPv4 is the protocol length for type IPv4 - 4.
	PLenIPv4 = 4
	// OperationRequest indicates OPER type ARP request
	OperationRequest uint16 = 1
	// OperationReply indicates OPER type ARP reply
	OperationReply uint16 = 2
)

// ArpTable is thread-safe ARP hashmap matching string IPv4 address to ArpEntries.
type ArpTable struct {
	ArpMap sync.Map
}

// ArpEntry contains IP to MAC addressing mapping determined via ARP protocol.
type ArpEntry struct {
	IP        net.IP
	Mac       net.HardwareAddr
	Status    ArpStatus
	Timestamp time.Time
}

// ArpStatus indicates if ARP has been sent or not
type ArpStatus int

const (
	// StatusWaiting indicates still waiting for an ARP response
	StatusWaiting ArpStatus = iota //0
	// StatusReady indicates ARP response was received
	StatusReady // 1
	// StatusStale Indicates timeout has been exceeded
	StatusStale // 2
)

// Add adds a new nil ArpEntry to the ArpTable syncmap.
func (t *ArpTable) Add(IP string) error {
	if IP == "" {
		return errors.New("valid IP address must be provided")
	}

	// Check if an entry already exist before adding one.
	_, ok := t.ArpMap.Load(IP)
	if ok == false {
		ip := net.ParseIP(IP)
		t.ArpMap.Store(IP, &ArpEntry{IP: ip, Mac: nil, Status: StatusWaiting, Timestamp: time.Now()})
	}
	return nil
}

// Update updates an ArpEntry in the ArpTable syncmap.
func (t *ArpTable) Update(IP string, mac net.HardwareAddr) error {
	if IP == "" {
		return errors.New("valid IP address must be provided")
	}
	ip := net.ParseIP(IP)
	t.ArpMap.Store(IP, &ArpEntry{IP: ip, Mac: mac, Status: StatusReady, Timestamp: time.Now()})
	return nil
}

// Get retrieves an ArpEntry in the ArpTable syncmap.
func (t *ArpTable) Get(IP string) (*ArpEntry, bool, error) {
	if IP == "" {
		return nil, false, errors.New("valid IP address must be provided")
	}
	rawEntry, found := t.ArpMap.Load(IP)
	if !found {
		return nil, false, nil
	}

	arpEntry, ok := rawEntry.(*ArpEntry)
	if !ok {
		return nil, false, errors.New("invalid ARP entry type")
	}
	return arpEntry, found, nil
}

// Remove removes an ArpEntry in the ArpTable syncmap.
func (t *ArpTable) Remove(IP string) error {
	if IP == "" {
		return errors.New("valid IP address must be provided")
	}
	t.ArpMap.Delete(IP)
	return nil
}

// ARPQueue is a thread-safe doubly-linked list buffer of ArpQueueEntries awaiting ARP replies.
// It is used to store queued-up packets awaiting an ARP response.
type ARPQueue struct {
	// embedded mutex
	sync.Mutex
	// embedded doubly-linked container list
	list.List
	// max length of buffer
	length uint
	// logger
	ll log.Logger
}

// ArpQueueEntry has string representation of IP along with buffers.
type ArpQueueEntry struct {
	IP   string
	buff []byte
}

// NewARPQueue creates and returns a new doubly-linked list of type ARPQueue.
func NewARPQueue(length uint) *ARPQueue {
	return &ARPQueue{
		length: length,
	}
}

// Add creates an entry and removes the oldest entry in the ARPQueue if queue length overflowed.
func (q *ARPQueue) Add(IP string, buff []byte) {
	q.Lock()
	defer q.Unlock()

	// If at max length, remove oldest element.
	if q.Len() == q.length {
		eOld := q.List.Back()
		q.List.Remove(eOld)
	}
	// Add to front
	q.List.PushFront(&ArpQueueEntry{IP, buff})
}

// Len return the current length of the container list.
func (q *ARPQueue) Len() uint {
	return uint(q.List.Len())
}

// Send returns a generic function to send provided frames to an connection.
func Send(conn net.Conn) func(buff []byte) error {
	return func(buff []byte) error {
		_, err := conn.Write(buff)
		if err != nil {
			return fmt.Errorf("unable to send conn: %v", err)
		}
		return nil
	}
}

// IterateAndRun take a function and passes all matched frames to it.
// This makes it far easier to test the iteration functionality.
func (q *ARPQueue) IterateAndRun(ip string, fn func([]byte) error) {
	q.Lock()
	defer q.Unlock()

	// Note: We are implementing no retries.
	e := q.List.Front()
	for e != nil {
		entry, ok := e.Value.(*ArpQueueEntry)
		if !ok {
			eTemp := e.Next()
			q.List.Remove(e)
			e = eTemp

			// TODO(sneha): properly log here
			fmt.Sprintln("invalid value in ARPQueue")
			continue
		}

		// Validate the frame length is at least 34 bytes or some minimum number
		if len(entry.buff) < 34 {
			eTemp := e.Next()
			q.List.Remove(e)
			e = eTemp

			// TODO(sneha): properly log here
			fmt.Sprintln("invalid frame length")
			continue
		}

		if entry.IP != ip {
			e = e.Next()
			continue
		}

		// If there is a match, send out bytes
		len := binary.BigEndian.Uint16(entry.buff[16:18])
		err := fn(entry.buff[0 : 14+len])
		if err != nil {
			fmt.Printf("unable to run function: %v\n", err)
		}

		eTemp := e.Next()
		q.List.Remove(e)
		e = eTemp
	}
}

// GenerateARPRequest crafts ARP Request from switch and dst IP and MAC address.
func GenerateARPRequest(arpTable *ArpTable, srcMAC []byte, dstIP string, srcIP string) ([]byte, error) {

	// FIXME this function should be .Upsert() (Add or Update the entry)
	err := arpTable.Add(dstIP)
	if err != nil {
		return nil, fmt.Errorf("unable to add waiting ARP entry: %v", err)
	}

	// Make space for nv header + ethernet header + ARP request
	frameBuf := make([]byte, 4+14+28)

	// nvHeader length value (the 2 bytes length field doesn't count so it's 2, not 4 byteshhh
	// for the nv header)
	binary.BigEndian.PutUint16(frameBuf[0:2], uint16(2+14+28))

	// nvHeader type frame
	binary.BigEndian.PutUint16(frameBuf[2:4], 1)

	// dst MAC address
	broadcast := [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	copy(frameBuf[4:10], broadcast[0:6])

	// src MAC address
	copy(frameBuf[10:16], srcMAC[0:6])

	// EtherType ARP
	binary.BigEndian.PutUint16(frameBuf[16:18], TypeARP)

	// ARP Hardware type (HTYPE), Ethernet is 1
	binary.BigEndian.PutUint16(frameBuf[18:20], HTypeEthernet)

	// ARP Protocol type (PTYPE), IPv4 is 0x0800
	binary.BigEndian.PutUint16(frameBuf[20:22], TypeIPv4)

	// Hardware len is 6 for ethernet
	// Protocol len is 4 for IPv4
	var HlenPlen uint16 = (HLenEthernet << 8) | PLenIPv4
	binary.BigEndian.PutUint16(frameBuf[22:24], HlenPlen)

	// ARP operation, request is 1
	binary.BigEndian.PutUint16(frameBuf[24:26], OperationRequest)

	// ARP Sender hardware address (SHA)
	copy(frameBuf[26:32], srcMAC[0:6])

	// ARP Sender protocol address (SPA)
	spa := net.ParseIP(srcIP).To4()
	copy(frameBuf[32:36], spa)

	// ARP Target hardware address (THA)
	// ignored in a request operation
	binary.BigEndian.PutUint16(frameBuf[36:38], 0x0)
	binary.BigEndian.PutUint16(frameBuf[38:40], 0x0)
	binary.BigEndian.PutUint16(frameBuf[40:42], 0x0)

	// ARP Target protocol address (TPA)
	tpa := net.ParseIP(dstIP).To4()
	copy(frameBuf[42:46], tpa)

	return frameBuf, nil
}

// GenerateARPReply crafts an ARP Reply
func GenerateARPReply(srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, spa net.IP, tpa net.IP) []byte {

	// Make space for nv header + ethernet header + ARP request
	frameBuf := make([]byte, 4+14+28)

	// nvHeader length value (the 2 bytes length field doesn't count so it's 2, not 4 byteshhh
	// for the nv header)
	binary.BigEndian.PutUint16(frameBuf[0:2], uint16(2+14+28))

	// nvHeader type frame
	binary.BigEndian.PutUint16(frameBuf[2:4], 1)

	// dst MAC address
	copy(frameBuf[4:10], dstMAC[0:6])

	// src MAC address
	copy(frameBuf[10:16], srcMAC[0:6])

	// EtherType ARP
	binary.BigEndian.PutUint16(frameBuf[16:18], TypeARP)

	// ARP Hardware type (HTYPE), Ethernet is 1
	binary.BigEndian.PutUint16(frameBuf[18:20], HTypeEthernet)

	// ARP Protocol type (PTYPE), IPv4 is 0x0800
	binary.BigEndian.PutUint16(frameBuf[20:22], TypeIPv4)

	// Hardware len is 6 for ethernet
	// Protocol len is 4 for IPv4
	var HlenPlen uint16 = (HLenEthernet << 8) | PLenIPv4
	binary.BigEndian.PutUint16(frameBuf[22:24], HlenPlen)

	// ARP operation, response is 2
	binary.BigEndian.PutUint16(frameBuf[24:26], OperationReply)

	// ARP Sender hardware address (SHA)
	copy(frameBuf[26:32], srcMAC)

	// ARP Sender protocol address (SPA)
	copy(frameBuf[32:36], spa)

	// ARP Target hardware address (THA)
	// ignored in a request operation
	copy(frameBuf[36:42], dstMAC)

	// ARP Target protocol address (TPA)
	copy(frameBuf[42:46], tpa)

	return frameBuf
}
