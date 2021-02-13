package main

import (
	"fmt"
	"net"

	ipv4 "golang.org/x/net/ipv4"
)

/* Note: This file contains utility functions for development and testing. */

func generateTestFrame() []byte {
	buff := make([]byte, 1518)
	// TODO(using fake encapsulated ARP packet for testing)
	hdr := ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen + 4,
		TOS:      1,
		TotalLen: 0xbef3,
		ID:       0xcafe,
		Flags:    ipv4.DontFragment,
		FragOff:  1500,
		TTL:      255,
		Protocol: 1,
		Checksum: 0xdead,
		Src:      net.ParseIP("198.18.0.5"), Dst: net.ParseIP("198.18.0.1"),
	}
	packetBuff, err := hdr.Marshal()
	if err != nil {
		fmt.Printf("unable to parse header: %v\n", err)
		continue
	}

	dstMAC := make([]byte, 6)
	srcMAC := make([]byte, 6) // TODO(sneha): change from hardcoded 0 values

	// add ethernet header
	copy(buff[0:6], dstMAC)
	copy(buff[6:12], srcMAC)
	copy(buff[12:14], etherTypeIPV4)

}

func generateTestARPReply() []byte {

}
