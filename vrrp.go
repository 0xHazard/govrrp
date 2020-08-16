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
)

const (
	advertisement         = 1            // The only VRRP message type
	vrrpVersion           = 3            // VRRP version
	vrrpHdrSize           = 8            // Lenght of VRRP header, bytes
	PseudoHeaderSize      = 12           // Size of pseudo-header, bytes
	VRRPprotoNumber       = 112          // The IP protocol number assigned by the IANA
	VRRPipv4MulticastAddr = "224.0.0.18" //The IP multicast address as assigned by the IANA
)

var (
	MaxAdvertIntDefault = 100 // centiseconds (100 eq 1 sec)
)

type Marshaler interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}

// VRRPpacket is a binary representation of VRRP packet
type VRRPpacket struct {
	PseudoHeader []byte
	Header       []byte
}

// VRRPmessage represents a VRRP message.
type VRRPmessage struct {
	Version       int
	Type          int
	VirtRouterID  int
	Priority      int
	CountIPv4     int
	Rsvd          int
	MaxAdvertInt  int
	Checksum      int
	IPv4addresses [][]byte
}

// IPv4PseudoHeader  represents IPv4 pseudo-header
type IPv4PseudoHeader struct {
	Src      []byte
	Dst      []byte
	Zero     uint8
	Protocol uint8
	VRRPLen  int
}

func (m *VRRPmessage) Marshal() (VRRPpacket, error) {
	if m == nil {
		return VRRPpacket{}, errNilHeader
	}
	b := make([]byte, vrrpHdrSize+(m.CountIPv4*4))

	// version | type fields
	b[0] = byte(vrrpVersion<<4 | advertisement)

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
	start := vrrpHdrSize
	for _, addr := range m.IPv4addresses {
		copy(b[start:], addr)
		start += 4
	}

	return VRRPpacket{
		Header: b,
	}, nil
}

func (m *VRRPmessage) Unmarshal(b []byte) error {
	if b == nil {
		return errNilHeader
	}

	if len(b) < vrrpHdrSize {
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
	b[3] = byte(m.CountIPv4)
	m.CountIPv4 = int(b[3])

	// rsvd | Max Adver Int
	m.Rsvd = int(b[4] >> 4)
	m.MaxAdvertInt = int((binary.BigEndian.Uint16(b[4:6])) ^ uint16(b[4])<<13)

	// Checksum
	m.Checksum = int(binary.BigEndian.Uint16(b[6:8]))

	// IP addresses
	ipAddrField := b[8:]
	for ; len(ipAddrField) >= 4; ipAddrField = ipAddrField[4:] {
		m.IPv4addresses = append(m.IPv4addresses, ipAddrField[0:4])
	}

	return nil
}

func (p *VRRPpacket) Marshal() ([]byte, error) {
	return append(p.PseudoHeader, p.Header...), nil
}

func (p *VRRPpacket) AddPseudoHeader(phdr []byte) {
	p.PseudoHeader = phdr
}

// SetChecksum writes provided checksum into Checksum field
func (p *VRRPpacket) SetChecksum(chksum uint16) {
	binary.BigEndian.PutUint16(p.Header[6:8], chksum)
}

//VerifyChecksum checks the checksum of incoming VRRP message according to rfc1071, returns True if the sum is valid, otherwise - false.
func VerifyChecksum(src, dst []byte, packet []byte) (bool, error) {
	// To calculate the checksum we need to add a pseudo-header as the original one was discarded.
	phdr := IPv4PseudoHeader{
		Src:      src,
		Dst:      dst,
		Protocol: VRRPprotoNumber,
		VRRPLen:  len(packet),
	}
	pkg := phdr.Marshal()
	pkg = append(pkg, packet...)
	chksum := Checksum(pkg)
	if chksum == uint16(0) {
		return true, nil
	}
	return false, nil
}

// Checksum calculates VRRP message checksum
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

//AddIPaddresses appends provided slice of IP addresses to VRRPmessage struct
func (m *VRRPmessage) AddIPaddresses(addresses [][]byte) error {
	for _, addr := range addresses {
		if len(addr) > 4 || addr[0] == 0 {
			return errInvalidIPv4Addr
		}
	}
	m.IPv4addresses = append(m.IPv4addresses, addresses...)
	m.CountIPv4 = len(addresses)
	return nil
}

func (hdr *IPv4PseudoHeader) Marshal() []byte {
	var b = make([]byte, PseudoHeaderSize)
	copy(b[0:4], hdr.Src)
	copy(b[4:8], hdr.Dst)
	b[8] = 0
	b[9] = byte(hdr.Protocol)
	binary.BigEndian.PutUint16(b[10:], uint16(hdr.VRRPLen))
	return b
}
