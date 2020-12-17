package govrrp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

type packet struct {
	name   string
	header ipv4.Header
	vrrp   VRRPmessage
	expect bool
}

var srcAddr = net.IPv4(127, 0, 0, 1).To4()

func TestAddIPaddresses(t *testing.T) {

	type addresses struct {
		addr   []net.IP
		count  int
		result bool
	}

	addrTable := []addresses{
		{[]net.IP{net.IPv4(192, 168, 8, 99).To4(), net.IPv4(172, 23, 44, 6).To4()}, 2, true},
		{[]net.IP{net.IPv4(192, 168, 8, 0).To4(), net.IPv4(192, 168, 8, 6).To4()}, 2, false},
		{[]net.IP{net.IPv4(172, 22, 2, 55).To4(), net.IPv4(172, 22, 2, 2).To4(), net.IPv4(192, 168, 3, 1).To4(), net.IPv4(192, 160, 6, 56).To4()}, 4, true},
		{[]net.IP{net.IPv4(0, 168, 8, 99).To4()}, 1, false},
		{[]net.IP{net.IPv4(0, 0, 0, 0).To4()}, 1, false},
	}

	testMessage := &VRRPmessage{}

	for _, addr := range addrTable {
		*testMessage = VRRPmessage{}
		err := testMessage.AddIPaddresses(addr.addr)
		if (err != nil && len(addr.addr) == addr.count && !addr.result) || (err == nil && (len(addr.addr) == addr.count) && addr.result) {
			t.Logf("PASSED: %v\n", addr)
		} else {
			t.Errorf("FAILED: %v\n", addr)
		}
	}
}

func TestMarshal(t *testing.T) {
	testMessage := &VRRPmessage{
		IPv4addresses: []net.IP{net.IPv4(172, 22, 2, 55).To4(), net.IPv4(192, 168, 3, 1).To4()},
		CountIPv4:     2,
	}

	vrrpMsg, err := testMessage.Marshal()
	if err != nil {
		t.Errorf("FAILED: %v\n", err)
	}

	var testAddr []byte
	for _, addr := range testMessage.IPv4addresses {
		testAddr = append(testAddr, addr...)
	}

	if bytes.Equal(vrrpMsg[8:], testAddr) {
		t.Logf("PASSED: %v\n", testMessage.IPv4addresses)
	} else {
		t.Errorf("FAILED: got %v; want %v\n", vrrpMsg[8:], testAddr)
	}

	if int(vrrpMsg[3]) == testMessage.CountIPv4 {
		t.Logf("PASSED: got: %d, expect: %d\n", int(vrrpMsg[3]), testMessage.CountIPv4)
	} else {
		t.Errorf("FAILED: got %d; want %d\n", vrrpMsg[3], testMessage.CountIPv4)
	}
}

func TestUnmarshal(t *testing.T) {
	const count = 2
	testMessage := &VRRPmessage{
		VirtRouterID:  3,
		IPv4addresses: []net.IP{net.IPv4(172, 22, 2, 55).To4(), net.IPv4(192, 168, 3, 1).To4()},
		CountIPv4:     count,
	}

	vrrpMsg, err := testMessage.Marshal()
	if err != nil {
		t.Errorf("FAILED: %v\n", err)
	}

	result := &VRRPmessage{}
	if err = result.Unmarshal(vrrpMsg); err != nil {
		t.Errorf("FAILED: couldn't unmarshal message: %v\n", err)
	}

	if result.VirtRouterID == testMessage.VirtRouterID && result.CountIPv4 == testMessage.CountIPv4 && len(result.IPv4addresses) == len(testMessage.IPv4addresses) {
		for idx, addr := range result.IPv4addresses {
			if !addr.Equal(testMessage.IPv4addresses[idx]) {
				t.Errorf("FAILED: got:%v; want: %v\n", addr, testMessage.IPv4addresses[idx])
				break
			}
		}
		t.Logf("PASSED: Unmarshaling VRRP message\n")
	} else {
		t.Errorf("FAILED: got:%v; want: %v\n", result, testMessage)
	}

	// Testing non-empty &VRRPmessage{}
	if err = result.Unmarshal(vrrpMsg); err != nil {
		t.Errorf("FAILED: couldn't unmarshal message: %v\n", err)
	}

	if result.VirtRouterID == testMessage.VirtRouterID && result.CountIPv4 == testMessage.CountIPv4 && len(result.IPv4addresses) == len(testMessage.IPv4addresses) {
		for idx, addr := range result.IPv4addresses {
			if !addr.Equal(testMessage.IPv4addresses[idx]) {
				t.Errorf("FAILED: got:%v; want: %v\n", addr, testMessage.IPv4addresses[idx])
				break
			}
		}
		t.Logf("PASSED: Unmarshaling VRRP message\n")
	} else {
		t.Errorf("FAILED: got:%v; want: %v\n", result, testMessage)
	}
}

func TestChecksum(t *testing.T) {
	type mcastPacket struct {
		iface           *net.Interface
		advertAddresses []net.IP
		result          bool
	}

	iface, err := GetInterface()
	if err != nil {
		t.Fatalf("FAILED: %v\n", err)
	}

	srcAddr, err := GetPrimaryIPv4addr(iface)

	if err != nil {
		t.Fatalf("FAILED: %v\n", err)
	}

	pcktTable := []mcastPacket{
		{iface, []net.IP{net.IPv4(192, 168, 8, 99).To4(), net.IPv4(172, 23, 44, 6).To4()}, true},
		{iface, []net.IP{net.ParseIP("ff02::114")}, false},
	}

	for _, tcase := range pcktTable {
		packet, err := NewVRRPmulticastPacket(tcase.iface, 2, tcase.advertAddresses)
		if err != nil {
			if !tcase.result {
				t.Logf("PASSED: %v\n", tcase)
				continue
			} else {
				t.Fatalf("FAILED: %v\n", err)
			}
		}

		pass, err := VerifyChecksum(srcAddr, net.ParseIP(VRRPipv4MulticastAddr).To4(), packet.VRRPpacket.Header)
		if err != nil {
			if !tcase.result {
				t.Logf("PASSED: %v\n", tcase)
				continue
			} else {
				t.Fatalf("FAILED: %v\n", err)
			}
		}
		if pass == tcase.result {
			t.Logf("PASSED: %v\n", tcase)
		} else {
			t.Errorf("FAILED: %v\n", tcase)
		}
	}
}

func TestValidate(t *testing.T) {
	testCase := []packet{
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

	for _, tcase := range testCase {
		t.Run(tcase.name, func(t *testing.T) {
			payload, err := checksumHelper(srcAddr, tcase.vrrp)
			require.NoError(t, err)
			result, err := Validate(&tcase.header, payload)
			if err != nil {
				assert.Equal(t, tcase.expect, result)
			}
			assert.Equal(t, tcase.expect, result)

		})
	}
}

func BenchmarkValidate(b *testing.B) {
	testData := packet{
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
	payload, err := checksumHelper(srcAddr, testData.vrrp)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		Validate(&testData.header, payload)
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
