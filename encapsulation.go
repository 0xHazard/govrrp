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

	"golang.org/x/net/ipv4"
)

// IPv4packet represents VRRPv3 message encapsulated in IPv4 packet with a control message. Ultimate structure that is used to describe the entire IPv4 packet with VRRP message in it.
type IPv4packet struct {
	ControlMessage *ipv4.ControlMessage
	IPv4header     *ipv4.Header
	VRRPpacket     *VRRPpacket
}

// VRRPpacket is a binary representation of VRRP packet
type VRRPpacket struct {
	PseudoHeader []byte
	Header       []byte
}

// NewVRRPmulticastPacket is a factory that returns IPv4packet that should be used for multicast purposes
func NewVRRPmulticastPacket(netif *net.Interface, vrid int, vips []net.IP) (*IPv4packet, error) {
	// getting primary IP address of the provided interface
	src, err := GetPrimaryIPv4addr(netif)
	if err != nil {
		return nil, err
	}

	// generating VRRP part of packet
	vrrpMessage := &VRRPmessage{
		Version:      vrrpVersion,
		Type:         advertisement,
		VirtRouterID: vrid,
		Priority:     255,
		CountIPv4:    0,
		Rsvd:         0,
		MaxAdvertInt: MaxAdvertIntDefault,
		Checksum:     0,
	}

	err = vrrpMessage.AddIPaddresses(vips)
	if err != nil {
		return nil, err
	}

	vrrp, err := vrrpMessage.Marshal()
	if err != nil {
		return nil, err
	}

	// pseudo-header
	pseudoHeader := &IPv4PseudoHeader{
		Src:      src,
		Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4(),
		Protocol: VRRPprotoNumber,
		VRRPLen:  len(vrrp),
	}

	phdr, err := pseudoHeader.Marshal()
	if err != nil {
		return nil, err
	}

	// IPv4 header
	IPv4header := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0xc0, // DSCP CS6
		TotalLen: ipv4.HeaderLen + len(vrrp),
		TTL:      255,
		Protocol: VRRPprotoNumber,
		Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4(),
	}

	// And a control message
	var cm *ipv4.ControlMessage
	cm = &ipv4.ControlMessage{
		Src:     src,
		IfIndex: netif.Index}

	// Calculating checksum
	chksum := Checksum(append(phdr, vrrp...))
	binary.BigEndian.PutUint16(vrrp[6:8], chksum)

	return &IPv4packet{
		ControlMessage: cm,
		IPv4header:     IPv4header,
		VRRPpacket: &VRRPpacket{
			PseudoHeader: phdr,
			Header:       vrrp,
		},
	}, nil
}

// GetVRRPpacket returns pseudo-header and VRRP message. That data is used for calculating the checksum
func (p *VRRPpacket) GetVRRPpacket() []byte {
	return append(p.PseudoHeader, p.Header...)
}

// SetPseudoHeader adds provided custom pseudo-header
func (p *VRRPpacket) SetPseudoHeader(phdr []byte) {
	p.PseudoHeader = phdr
}

// SetChecksum writes provided checksum into Checksum field
func (p *VRRPpacket) SetChecksum(chksum uint16) {
	binary.BigEndian.PutUint16(p.Header[6:8], chksum)
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
