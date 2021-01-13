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
	"net"
)

const (
	IPversion   = 4
	IPheaderLen = 20 // header length without extension headers
)

// IPv4header represents IPv4 header. Copy-pasted from x/net/ipv4 package.
type IPv4header struct {
	Version  int    // protocol version
	Len      int    // header length
	TOS      int    // type-of-service
	TotalLen int    // packet total length
	ID       int    // identification
	Flags    int    // flags
	FragOff  int    // fragment offset
	TTL      int    // time-to-live
	Protocol int    // next protocol
	Checksum int    // checksum
	Src      net.IP // source address
	Dst      net.IP // destination address
	Options  []byte // options, extension headers
}

// Marshal encodes IPv4header struct to it's binary representation
func (h *IPv4header) Marshal() ([]byte, error) {
	if h == nil {
		return nil, errNilHeader
	}

	hdrlen := IPheaderLen + len(h.Options)
	b := make([]byte, hdrlen)
	b[0] = byte(IPversion<<4 | (hdrlen >> 2 & 0x0f))
	b[1] = byte(h.TOS)
	binary.BigEndian.PutUint16(b[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.ID))
	flagsAndOffset := (h.FragOff & 0x1fff) | int(h.Flags<<13)
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndOffset))
	b[8] = byte(h.TTL)
	b[9] = byte(h.Protocol)
	binary.BigEndian.PutUint16(b[10:12], uint16(h.Checksum))
	copy(b[12:16], h.Src.To4())
	copy(b[16:20], h.Dst.To4())
	if len(h.Options) > 0 {
		copy(b[IPheaderLen:], h.Options)
	}
	return b, nil
}

// Unmarshal decodes  IPv4 header to IPv4header struct
func (h *IPv4header) Unmarshal(b []byte) error {
	if h == nil || b == nil {
		return errNilHeader
	}

	hdrlen := int(b[0]&0x0f) << 2
	if len(b) < hdrlen {
		return errBadIPheader
	}

	h.Version = int(b[0] >> 4)
	h.Len = hdrlen
	h.TOS = int(b[1])
	h.TotalLen = int(binary.BigEndian.Uint16(b[2:4]))
	h.ID = int(binary.BigEndian.Uint16(b[4:6]))
	h.FragOff = int(binary.BigEndian.Uint16(b[6:8]))
	h.TTL = int(b[8])
	h.Protocol = int(b[9])
	h.Checksum = int(binary.BigEndian.Uint16(b[10:12]))
	h.Flags = int(h.FragOff&0xe000) >> 13
	h.FragOff = h.FragOff & 0x1fff
	h.Src = net.IPv4(b[12], b[13], b[14], b[15])
	h.Dst = net.IPv4(b[16], b[17], b[18], b[19])
	optlen := hdrlen - IPheaderLen
	if optlen > 0 && len(b) >= hdrlen {
		if cap(h.Options) < optlen {
			h.Options = make([]byte, optlen)
		} else {
			h.Options = h.Options[:optlen]
		}
		copy(h.Options, b[IPheaderLen:hdrlen])
	}
	return nil
}

// NewIPmulticastPacket is a factory that returns IPv4 packet containing VRRP message as payload that should be used for multicast purpose
func NewIPmulticastPacket(netif *net.Interface, vrid, priority int, vips []net.IP) ([]byte, error) {
	// getting primary IP address of the provided interface
	src, err := GetPrimaryIPv4addr(netif)
	if err != nil {
		return nil, err
	}

	// generating VRRP part of packet
	Message := &Message{
		Version:      version,
		Type:         advertisement,
		VirtRouterID: vrid,
		Priority:     priority,
		CountIPv4:    0,
		Rsvd:         0,
		MaxAdvertInt: MaxAdvertIntDefault,
		Checksum:     0,
	}

	err = Message.AddIPaddresses(vips)
	if err != nil {
		return nil, err
	}

	vrrp, err := Message.Marshal()
	if err != nil {
		return nil, err
	}

	// pseudo-header
	pseudoHeader := &IPv4PseudoHeader{
		Src:      src.To4(),
		Dst:      McastGroup,
		Protocol: ProtoNumber,
		VRRPLen:  len(vrrp),
	}

	phdr, err := pseudoHeader.Marshal()
	if err != nil {
		return nil, err
	}

	// IPv4 header
	IPv4header := &IPv4header{
		Version:  IPversion,
		Len:      IPheaderLen,
		TOS:      0xc0, // DSCP CS6
		TotalLen: IPheaderLen + len(vrrp),
		TTL:      255,
		Protocol: ProtoNumber,
		Src:      src.To4(),
		Dst:      McastGroup,
	}

	ip4b, err := IPv4header.Marshal()
	if err != nil {
		return nil, err
	}

	// Calculating checksum
	chksum := Checksum(append(phdr, vrrp...))
	binary.BigEndian.PutUint16(vrrp[6:8], chksum)

	return append(ip4b, vrrp...), nil
}

// GetPrimaryIPv4addr returns primary IPv4 address of provided interface
func GetPrimaryIPv4addr(netif *net.Interface) (net.IP, error) {
	ifAddr, err := netif.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range ifAddr {
		if ipv4 := addr.(*net.IPNet).IP.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}
	return nil, errIfNoIPv4addr
}

// GetInterface looks for the default network interface to use. The first match that is up and has Broadcast and Multicast flags will be returned.
func GetInterface() (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifs {
		if iface.Flags == net.FlagUp|net.FlagBroadcast|net.FlagMulticast {
			return &iface, nil
		}
	}
	return nil, errIfNotFound
}

// Decapsulate extracts IPv4 header and VRRP message, returns slices of bytes that can be unmarshaled with corresponding methods
func Decapsulate(p []byte) (ipHeader, vrrp []byte, err error) {
	if p == nil {
		return nil, nil, errNilHeader
	}

	ipHdrlen := int(p[0]&0x0f) << 2

	ipHeader = p[:ipHdrlen]
	vrrp = p[ipHdrlen:]
	return
}
