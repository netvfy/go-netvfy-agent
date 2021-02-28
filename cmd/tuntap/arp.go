package main

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

// ARPQueue is a thread-safe doubly-linked list buffer of ArpQueueEntries awaiting ARP replies.
type ARPQueue struct {
	// embedded mutex
	sync.Mutex
	// embedded doubly-linked container list
	list.List
	// max length of buffer
	length int
	// logger
	ll log.Logger
}

// ArpQueueEntry has string representation of IP along with buffers
type ArpQueueEntry struct {
	IP   string
	buff []byte
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
func (q *ARPQueue) Add(IP string, buff []byte) {
	q.Lock()
	defer q.Unlock()
	// TODO
	// If overflowed, remove back
	if q.Len() > q.length {
		eOld := q.List.Back()
		q.List.Remove(eOld)
	}
	// Add to front
	q.List.PushFront(&ArpQueueEntry{IP, buff})
}

// Len return the current length of the container list.
func (q *ARPQueue) Len() int {
	return q.List.Len()
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
// TODO(sneha): iteration is a bit broken
func (q *ARPQueue) IterateAndRun(ip string, fn func([]byte) error) {
	q.Lock()
	defer q.Unlock()

	fmt.Println("Starting shit here")
	count := 0
	// Note: We are implementing no retries.
	e := q.List.Front()
	for e != nil {
		if count == 5 {
			break
		}

		fmt.Println("are we here a")
		entry, ok := e.Value.(*ArpQueueEntry)
		if !ok {
			fmt.Println("is thi happening")
			// TODO: log that this is invalid
			eTemp := e.Next()
			q.List.Remove(e)
			e = eTemp
			count++
			continue
		}

		// Validate the frame length is at least 34 bytes or some minimum number
		if len(entry.buff) < 34 {
			eTemp := e.Next()
			q.List.Remove(e)
			e = eTemp
			count++
			continue
		}

		if entry.IP != ip {
			e = e.Next()
			count++
			continue
		}

		// If there is a match, send out bytes
		// TODO - cannot seem to properly parse this at all- endianness issue?
		len := binary.BigEndian.Uint16(entry.buff[16:18])
		fmt.Println(len)
		fmt.Println("adding code in here")
		err := fn(entry.buff[0 : 14+len])
		if err != nil {
			// TODO(sneha): log an error
		}

		e = e.Next()
		count++
	}
}