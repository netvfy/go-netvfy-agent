package main

import (
	"container/list"
	"net"
	"sync"
	"time"
)

// ArpTable is thread-safe ARP hashmap matching string IPv4 address to MAC addresses.
var ArpTable sync.Map

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

// ARPQueue is a thread-safe doubly-linked list buffer of of IP addresses waiting for ARP responses.
type ARPQueue struct {
	// embedded mutex
	sync.Mutex
	// embedded container list
	list.List
	// max length of buffer
	length int
}

func (q *ARPQueue) Add(buff []byte) {

}
