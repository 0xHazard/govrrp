// Copyright 2020 govrrp authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package govrrp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const Centisecond time.Duration = 10 * time.Millisecond

const (
	advertisement    = 1   // The only VRRP message type
	version          = 3   // VRRP version
	hdrSize          = 8   // Lenght of VRRP header, bytes
	PseudoHeaderSize = 12  // Size of pseudo-header, bytes
	ProtoNumber      = 112 // The IP protocol number assigned by the IANA
	// VRRPipv4MulticastAddr = "224.0.0.18"
)

var (
	MaxAdvertIntDefault = 100                           // centiseconds (100 eq 1 sec)
	McastGroup          = net.IPv4(224, 0, 0, 18).To4() // The IP multicast address as assigned by the IANA
)

// Message represents a VRRP message.
type Message struct {
	Version       int
	Type          int
	VirtRouterID  int
	Priority      int
	CountIPv4     int
	Rsvd          int
	MaxAdvertInt  int
	Checksum      int
	IPv4addresses []net.IP
}

// IPv4PseudoHeader  represents IPv4 pseudo-header
type IPv4PseudoHeader struct {
	Src      []byte
	Dst      []byte
	Zero     uint8
	Protocol uint8
	VRRPLen  int
}

// Marshal converts Message struct to it's binary representation that will be used in the packet
func (m *Message) Marshal() ([]byte, error) {
	if m == nil {
		return nil, errNilHeader
	}

	m.CountIPv4 = len(m.IPv4addresses)
	b := make([]byte, hdrSize+(m.CountIPv4*4))

	// version | type fields
	b[0] = byte(version<<4 | advertisement)

	// VRID
	b[1] = byte(m.VirtRouterID)

	// Priority
	b[2] = byte(m.Priority)

	// IP addr count
	b[3] = byte(m.CountIPv4)

	// rsvd | Max Adver Int
	rsvcAndMaxAdvertInt := (m.MaxAdvertInt) | int(m.Rsvd<<13&0x00)
	binary.BigEndian.PutUint16(b[4:6], uint16(rsvcAndMaxAdvertInt))

	// Checksum
	binary.BigEndian.PutUint16(b[6:8], uint16(m.Checksum))

	// IP addresses
	start := hdrSize
	for _, addr := range m.IPv4addresses {
		copy(b[start:], addr.To4())
		start += 4
	}

	return b, nil
}

// Unmarshal reads a binary representation of VRRP message and fills up Message structure that's provided as a receiver
func (m *Message) Unmarshal(b []byte) error {
	if b == nil || m == nil {
		return errNilHeader
	}

	if len(b) < hdrSize {
		return errShortHeader
	}

	// version | type fields
	m.Version = int(b[0] >> 4)
	m.Type = int(b[0] & 0xf)

	// VRID
	m.VirtRouterID = int(b[1])

	// Priority
	m.Priority = int(b[2])

	// IP addr count
	m.CountIPv4 = int(b[3])

	// rsvd | Max Adver Int
	m.Rsvd = int(b[4] >> 4)
	m.MaxAdvertInt = int((binary.BigEndian.Uint16(b[4:6])) ^ uint16(b[4])<<13)

	// Checksum
	m.Checksum = int(binary.BigEndian.Uint16(b[6:8]))

	// IP addresses
	m.IPv4addresses = nil
	ipAddrField := b[8:]
	for ; len(ipAddrField) >= 4; ipAddrField = ipAddrField[4:] {
		m.IPv4addresses = append(m.IPv4addresses, ipAddrField[0:4])
	}

	return nil
}

//VerifyChecksum checks the checksum of incoming VRRP message according to rfc1071, returns True if the sum is valid, otherwise - false.
func VerifyChecksum(src, dst net.IP, vrrp []byte) (bool, error) {
	// src and dst IPs must be 4-byte slices, otherwise VerifyChecksum() fails
	src = src.To4()
	dst = dst.To4()
	if src == nil || dst == nil {
		return false, errInvalidIPv4Addr
	}
	// To calculate the checksum we need to add a pseudo-header as the original one was discarded.
	phdr := &IPv4PseudoHeader{
		Src:      src,
		Dst:      dst,
		Protocol: ProtoNumber,
		VRRPLen:  len(vrrp),
	}
	pkg, err := phdr.Marshal()
	if err != nil {
		return false, err
	}

	pkg = append(pkg, vrrp...)
	chksum := Checksum(pkg)
	if chksum == uint16(0) {
		return true, nil
	}
	return false, nil
}

//AddIPaddresses appends provided slice of IP addresses that will be advertised to Message struct
func (m *Message) AddIPaddresses(addresses []net.IP) error {
	for _, addr := range addresses {
		if ipv4 := addr.To4(); ipv4 == nil || ipv4[0] == 0 || ipv4[3] == 0 {
			return errInvalidIPv4Addr
		}
	}
	m.IPv4addresses = append(m.IPv4addresses, addresses...)
	m.CountIPv4 = len(addresses)
	return nil
}

// Marshal converts IPv4PseudoHeader struct into it's binary representation that will be used in the packet
func (hdr *IPv4PseudoHeader) Marshal() ([]byte, error) {
	var b = make([]byte, PseudoHeaderSize)
	copy(b[0:4], hdr.Src)
	copy(b[4:8], hdr.Dst)
	b[8] = 0
	b[9] = byte(hdr.Protocol)
	binary.BigEndian.PutUint16(b[10:], uint16(hdr.VRRPLen))
	return b, nil
}

// Checksum calculates checksum of provided VRRP message.
func Checksum(b []byte) uint16 {
	var sum uint32
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(b[0])<<8 | uint32(b[1])
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// Validate checks if the incoming packet should be accepted.
func Validate(h *IPv4header, p []byte) (bool, error) {
	if h == nil || p == nil {
		return false, errIsNil
	}

	if h.Version != 4 {
		return false, errIfNoIPv4
	}

	// TTL should be equal to 255
	if h.TTL != 255 {
		return false, errBadIPttl
	}

	// Check VRRP version
	if p[0] != byte(version<<4|advertisement) {
		return false, errInvalidVRRPversion
	}
	valid, err := VerifyChecksum(h.Src, h.Dst, p)
	if err != nil {
		return false, fmt.Errorf("%s: %s", errBadChecksum, err)
	}
	if !valid {
		return false, errBadChecksum
	}

	return true, nil
}

// Centiseconds returns the duration as an integer centiseconds count.
func Centiseconds(d time.Duration) int64 {
	return int64(d) / 1e7
}

// NewVRRPpacket is a factory that returns VRRP message
// with calculated checksum. Can be used for either multicast or unicast.
func NewVRRPpacket(src, dst net.IP, vrid int, vips []net.IP) ([]byte, error) {

	if src == nil || dst == nil {
		return nil, errIsNil
	}

	msg := &Message{
		Version:      version,
		Type:         advertisement,
		VirtRouterID: vrid,
		Priority:     255,
		CountIPv4:    0,
		Rsvd:         0,
		MaxAdvertInt: MaxAdvertIntDefault,
		Checksum:     0,
	}

	err := msg.AddIPaddresses(vips)
	if err != nil {
		return nil, err
	}

	vrrp, err := msg.Marshal()
	if err != nil {
		return nil, err
	}

	pseudoHeader := &IPv4PseudoHeader{
		Src:      src.To4(),
		Dst:      dst.To4(),
		Protocol: ProtoNumber,
		VRRPLen:  len(vrrp),
	}

	phdr, err := pseudoHeader.Marshal()
	if err != nil {
		return nil, err
	}

	// Calculating checksum
	chksum := Checksum(append(phdr, vrrp...))
	binary.BigEndian.PutUint16(vrrp[6:8], chksum)

	return vrrp, nil
}
