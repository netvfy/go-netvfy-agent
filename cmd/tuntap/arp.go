package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// ArpTable is thread-safe ARP hashmap matching string IPv4 address to MAC addresses.
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

	ip := net.ParseIP(IP)
	t.ArpMap.Store(IP, &ArpEntry{IP: ip, Mac: nil, Status: StatusWaiting, Timestamp: time.Now()})
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

// ARPQueue is a thread-safe doubly-linked list buffer of of IP addresses waiting for ARP responses.
type ARPQueue struct {
	// embedded mutex
	sync.Mutex
	// embedded doubly-linked container list
	list.List
	// max length of buffer
	length int
}

// NewARPQueue creates and returns a new doubly-linked list of type ARPQueue.
func NewARPQueue(length int) (*ARPQueue, error) {
	if length <= 0 {
		return nil, errors.New("maximum queue length must be greater than 0")
	}
	return &ARPQueue{
		length: length,
	}, nil
}

// Add creates an entry and removes the oldest entry in the ARPQueue if queue length overflowed.
func (q *ARPQueue) Add(buff []byte) {
	q.Mutex.Lock()
	defer q.Mutex.Unlock()
	// TODO
	// If overflowed, remove back
	if q.Len() > q.length {
		eOld := q.List.Back()
		q.List.Remove(eOld)
	}

	// Add to front
	q.List.PushFront(buff)
}

// Len return the current length of the container list.
func (q *ARPQueue) Len() int {
	return q.List.Len()
}

// SendAndRemove take a conn struct to attempt to send and remove all matched frames.
func (q *ARPQueue) SendAndRemove(conn net.Conn, ip net.IP, hwAddr net.HardwareAddr) {
	q.Lock()
	defer q.Unlock()

	// Note: We are implementing no retries.
	e := q.List.Front()
	for e != nil {
		buff, ok := e.Value.([]byte)
		if !ok {
			// TODO: log that this is invalid
			eOld := e
			e = e.Next().Next()
			q.List.Remove(eOld)
			continue
		}

		// Validate the frame length is at least 34 bytes or some minimum number
		if len(buff) < 34 {
			eOld := e
			e = e.Next().Next()
			q.List.Remove(eOld)
			continue
		}

		if bytes.Compare(buff[30:34], ip) != 0 {
			continue
		}

		// If there is a match, send out bytes
		len := binary.BigEndian.Uint16(buff[16:18])
		_, err := conn.Write(buff[0 : 14+len])
		if err != nil {
			// TODO log that this is invalid
		}

		eOld := e
		e = e.Next().Next()
		q.List.Remove(eOld)
	}
}
