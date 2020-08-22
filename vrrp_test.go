package govrrp

import (
	"bytes"
	"net"
	"testing"
)

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
		t.Logf("PASSED: %v\n", testMessage.CountIPv4)
	} else {
		t.Errorf("FAILED: got %d; want %d\n", vrrpMsg[3], testMessage.CountIPv4)
	}
}

func TestNewVRRPmulticastPacket(t *testing.T) {
	type mcastPacket struct {
		iface           *net.Interface
		advertAddresses []net.IP
		result          bool
	}

	iface, err := GetInterface()
	if err != nil {
		t.Fatalf("FAILED: %v\n", err)
	}

	pcktTable := []mcastPacket{
		{iface, []net.IP{net.IPv4(192, 168, 8, 99), net.IPv4(172, 23, 44, 6)}, true},
		{iface, []net.IP{net.ParseIP("ff02::114")}, false},
	}

	for _, tcase := range pcktTable {
		_, err := NewVRRPmulticastPacket(tcase.iface, 2, tcase.advertAddresses)

		// TODO ...
		// just a placeholder for now
		if (err != nil) || (err == nil && tcase.result) || (err == nil && !tcase.result) {
			t.Logf("PASSED %v\n", tcase)
		} else {
			t.Errorf("FAILED Got: %v Expected %v; Error: %v\n", !tcase.result, tcase.result, err)
		}
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
				t.Logf("PASSED %v\n", tcase)
				continue
			} else {
				t.Fatalf("FAILED %v\n", err)
			}
		}
		vrrp, err := packet.VRRPpacket.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		csum := Checksum(vrrp)
		packet.VRRPpacket.SetChecksum(csum)

		pass, err := VerifyChecksum(srcAddr, net.ParseIP(VRRPipv4MulticastAddr).To4(), packet.VRRPpacket.Header)
		if err != nil {
			if !tcase.result {
				t.Logf("PASSED %v\n", tcase)
				continue
			} else {
				t.Fatalf("FAILED %v\n", err)
			}
		}
		if pass == tcase.result {
			t.Logf("PASSED %v\n", tcase)
		} else {
			t.Errorf("FAILED %v\n", tcase)
		}
	}
}
