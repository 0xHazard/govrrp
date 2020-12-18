package govrrp

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

func TestAddIPaddresses(t *testing.T) {
	type addresses struct {
		addr  []net.IP
		count int
	}

	type table struct {
		name   string
		given  addresses
		expect addresses
	}

	tests := []table{
		{
			name: "Valid case",
			given: addresses{
				[]net.IP{net.IPv4(192, 168, 8, 99).To4(), net.IPv4(172, 23, 44, 6).To4()},
				2,
			},
			expect: addresses{
				[]net.IP{net.IPv4(192, 168, 8, 99).To4(), net.IPv4(172, 23, 44, 6).To4()},
				2,
			},
		},
		{
			name: "Subnet address",
			given: addresses{
				[]net.IP{net.IPv4(192, 168, 8, 0).To4(), net.IPv4(192, 168, 8, 6).To4()},
				2,
			},
			expect: addresses{
				nil,
				0,
			},
		},
		{
			name: "Invalid IPv4 address",
			given: addresses{
				[]net.IP{net.IPv4(0, 168, 8, 99).To4()},
				1,
			},
			expect: addresses{
				nil,
				0,
			},
		},
		{
			name: "Meta-address",
			given: addresses{
				[]net.IP{net.IPv4(0, 0, 0, 0).To4()},
				1,
			},
			expect: addresses{
				nil,
				0,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &VRRPmessage{}
			err := result.AddIPaddresses(tc.given.addr)
			if err != nil && err != errInvalidIPv4Addr {
				t.Fatal(err)
			}
			assert.Equal(t, tc.expect.addr, result.IPv4addresses)
			assert.Equal(t, tc.expect.count, result.CountIPv4)

		})
	}
}

func TestMarshal(t *testing.T) {
	tests := struct {
		message VRRPmessage
		given   []byte
		expect  []byte
	}{
		VRRPmessage{
			IPv4addresses: []net.IP{net.IPv4(172, 22, 2, 55).To4(), net.IPv4(192, 168, 3, 1).To4()},
			CountIPv4:     2,
		},
		[]byte{},
		[]byte{},
	}

	given, err := tests.message.Marshal()
	require.NoError(t, err)

	for _, addr := range tests.message.IPv4addresses {
		tests.expect = append(tests.expect, addr...)
	}
	// check only payload
	assert.Equal(t, tests.expect, given[8:])
	assert.Equal(t, tests.message.CountIPv4, int(given[3]))
}

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name   string
		given  VRRPmessage
		expect VRRPmessage
	}{
		{
			"Common functionality",
			VRRPmessage{},
			VRRPmessage{
				Version:       3,
				Type:          1,
				VirtRouterID:  3,
				IPv4addresses: []net.IP{net.IPv4(172, 22, 2, 55).To4(), net.IPv4(192, 168, 3, 1).To4()},
				CountIPv4:     2,
			},
		},
		{
			"Non-empty structure",
			VRRPmessage{
				Version:       3,
				Type:          1,
				VirtRouterID:  3,
				IPv4addresses: []net.IP{net.IPv4(172, 1, 1, 1).To4(), net.IPv4(192, 2, 2, 2).To4()},
				CountIPv4:     2,
			},
			VRRPmessage{
				Version:       3,
				Type:          1,
				VirtRouterID:  3,
				IPv4addresses: []net.IP{net.IPv4(172, 22, 2, 55).To4(), net.IPv4(192, 168, 3, 1).To4()},
				CountIPv4:     2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			given, err := tt.expect.Marshal()
			require.NoError(t, err)

			err = tt.given.Unmarshal(given)
			require.NoError(t, err)

			assert.Equal(t, tt.expect, tt.given)
		})
	}
}

func TestChecksum(t *testing.T) {
	iface, err := GetInterface()
	require.NoError(t, err)

	srcAddr, err := GetPrimaryIPv4addr(iface)
	require.NoError(t, err)

	tests := []struct {
		name      string
		src       net.IP
		iface     *net.Interface
		addresses []net.IP
		expect    bool
	}{
		{"Valid case",
			srcAddr, iface, []net.IP{net.IPv4(192, 168, 8, 99).To4(), net.IPv4(172, 23, 44, 6).To4()}, true},
		{"Non 4-byte src IP addr representation",
			srcAddr.To16(), iface, []net.IP{net.IPv4(192, 168, 8, 99), net.IPv4(172, 23, 44, 6)}, true},
		{"IPv6 check",
			srcAddr, iface, []net.IP{net.ParseIP("ff02::114")}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := NewVRRPmulticastPacket(tc.iface, 2, tc.addresses)
			if err != nil {
				require.Equal(t, tc.expect, false)
				return
			}

			result, err := VerifyChecksum(tc.src, net.ParseIP(VRRPipv4MulticastAddr).To4(), packet.VRRPpacket.Header)
			if err != nil {
				require.Equal(t, tc.expect, false)
				return
			}
			require.Equal(t, tc.expect, result)

		})
	}
}

func TestValidate(t *testing.T) {
	type packet struct {
		name   string
		header ipv4.Header
		vrrp   VRRPmessage
		expect bool
	}

	var srcAddr = net.IPv4(127, 0, 0, 1).To4()

	tests := []packet{
		{
			"Valid package",
			ipv4.Header{
				Version:  ipv4.Version,
				Src:      srcAddr,
				TTL:      255,
				Protocol: VRRPprotoNumber,
				Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4()},
			VRRPmessage{
				Version:       vrrpVersion,
				Type:          advertisement,
				VirtRouterID:  2,
				Priority:      255,
				CountIPv4:     1,
				Rsvd:          0,
				MaxAdvertInt:  MaxAdvertIntDefault,
				Checksum:      0,
				IPv4addresses: []net.IP{net.IPv4(192, 168, 8, 99).To4()}},
			true,
		},
		{
			"Not IPv4 packet",
			ipv4.Header{
				Version:  6,
				TTL:      255,
				Protocol: VRRPprotoNumber,
				Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4()}, VRRPmessage{},
			false,
		},
		{
			"TTL is not 255",
			ipv4.Header{
				Version:  ipv4.Version,
				Protocol: VRRPprotoNumber,
				Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4()}, VRRPmessage{},
			false,
		},
		{
			"IP version is undefined",
			ipv4.Header{
				TTL:      255,
				Protocol: VRRPprotoNumber,
				Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4()}, VRRPmessage{},
			false,
		},
		{
			"Unsupported VRRP version",
			ipv4.Header{
				Version:  ipv4.Version,
				TTL:      255,
				Protocol: VRRPprotoNumber,
				Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4()},
			VRRPmessage{
				Version:      2,
				Type:         advertisement,
				VirtRouterID: 2,
				Priority:     255,
				Checksum:     0},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := checksumHelper(srcAddr, tc.vrrp)
			require.NoError(t, err)
			result, err := Validate(&tc.header, payload)
			if err != nil {
				assert.Equal(t, tc.expect, result)
			}
			assert.Equal(t, tc.expect, result)

		})
	}
}

func BenchmarkValidate(b *testing.B) {
	type packet struct {
		name   string
		header ipv4.Header
		vrrp   VRRPmessage
		expect bool
	}

	var srcAddr = net.IPv4(127, 0, 0, 1).To4()

	tests := packet{
		"Valid bench test",
		ipv4.Header{
			Version:  ipv4.Version,
			Src:      srcAddr,
			TTL:      255,
			Protocol: VRRPprotoNumber,
			Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4()},
		VRRPmessage{
			Version:       vrrpVersion,
			Type:          advertisement,
			VirtRouterID:  2,
			Priority:      255,
			CountIPv4:     1,
			Rsvd:          0,
			MaxAdvertInt:  MaxAdvertIntDefault,
			Checksum:      0,
			IPv4addresses: []net.IP{net.IPv4(192, 168, 8, 99).To4()},
		},
		true,
	}
	payload, err := checksumHelper(srcAddr, tests.vrrp)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		Validate(&tests.header, payload)
	}
}

func checksumHelper(src net.IP, vrrp VRRPmessage) ([]byte, error) {
	payload, err := vrrp.Marshal()
	if err != nil {
		return nil, err
	}

	// pseudo-header
	pseudoHeader := &IPv4PseudoHeader{
		Src:      src,
		Dst:      net.ParseIP(VRRPipv4MulticastAddr).To4(),
		Protocol: VRRPprotoNumber,
		VRRPLen:  len(payload),
	}

	phdr, err := pseudoHeader.Marshal()
	if err != nil {
		return nil, err
	}

	// Calculating checksum
	chksum := Checksum(append(phdr, payload...))
	binary.BigEndian.PutUint16(payload[6:8], chksum)
	return payload, nil
}
