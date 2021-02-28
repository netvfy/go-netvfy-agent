package main

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
)

/* Note: This file contains utility functions for development and testing. */
var (
	testIP = "198.18.0.5"
)

func generateTestFrame() ([]byte, error) {
	buff := make([]byte, 1518)
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
		return nil, fmt.Errorf("unable to parse header: %v", err)
	}

	dstMAC := make([]byte, 6)
	srcMAC := make([]byte, 6) // TODO(sneha): change from hardcoded 0 values

	// add ethernet header
	copy(buff[0:6], dstMAC)
	copy(buff[6:12], srcMAC)
	copy(buff[12:14], etherTypeIPV4)
	copy(buff[14:14+hdr.Len], packetBuff)

	return buff, nil
}

// func generateTestARPReply() []byte {
//
// }
