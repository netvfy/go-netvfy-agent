package main

import (
	"encoding/binary"
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
		Len:      ipv4.HeaderLen,
		TOS:      1,
		TotalLen: 0xbef3,
		ID:       0xcafe,
		Flags:    ipv4.DontFragment,
		FragOff:  1500,
		TTL:      255,
		Protocol: 1,
		Checksum: 0xdead,
		Src:      net.ParseIP("198.18.0.5"),
		Dst:      net.ParseIP("198.18.0.1"),
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

	fmt.Println(binary.BigEndian.Uint16(buff[16:18]))
	// TODO - tests are breaking b/c of this -> I can't seem to get the length from the buffered header irrespective of byte order i'm trying
	fmt.Println(binary.LittleEndian.Uint16(packetBuff[0:2]))
	fmt.Println(binary.BigEndian.Uint16(packetBuff[2:4]))

	return buff[0 : 14+hdr.Len], nil
}

// func generateTestARPReply() []byte {
//
// }
