package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
)

/* Note: This file contains utility functions for development and testing. */
var (
	testIP  = "198.18.0.5"
	testIP2 = "198.18.0.6"
	testIP3 = "198.18.0.7"
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

// Marshall generates byte slice from IPv4 header in the network byte order (Big Endian).
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
func generateTestFrame() ([]byte, error) {
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

	return buff[0 : 14+hdr.Len], nil
}

// func generateTestARPReply() []byte {
//
// }
