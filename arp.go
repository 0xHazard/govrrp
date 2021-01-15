package govrrp

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

const (
	ArpRequest = iota + 1
	ArpReply
)

const (
	frameLen  int = 44
	ipAddrLen int = 4
	hwAddrLen int = 6
)

var (
	BcastHWaddr []byte = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type ArpPacket struct {
	TargetIPaddr []byte
	IfaceIndex   int
	IfaceIPaddr  []byte
	IfaceHWaddr  []byte
	ArpType      uint16
}

// Marshal converts ArpPacket struct into binary representation
func (p *ArpPacket) Marshal() []byte {
	packet := make([]byte, frameLen)
	// Crafting Ethernet header
	copy(packet[0:6], BcastHWaddr)
	copy(packet[6:12], p.IfaceIPaddr)
	binary.BigEndian.PutUint16(packet[12:14], uint16(unix.ETH_P_ARP))

	// ARP itself
	binary.BigEndian.PutUint16(packet[14:16], uint16(unix.ARPHRD_ETHER))
	binary.BigEndian.PutUint16(packet[16:18], uint16(unix.ETH_P_IP))
	packet[18] = byte(hwAddrLen)
	packet[19] = byte(ipAddrLen)

	binary.BigEndian.PutUint16(packet[20:22], p.ArpType)
	copy(packet[22:28], p.IfaceHWaddr)
	copy(packet[28:32], p.TargetIPaddr)
	copy(packet[32:38], BcastHWaddr)
	copy(packet[38:44], p.TargetIPaddr)

	return packet
}

// We expect little-endian system
func htons(i uint16) uint16 {
	// Swap bytes in 16-bit value
	return (((i) >> 8) & 0xff) | (((i) & 0xff) << 8)
}
