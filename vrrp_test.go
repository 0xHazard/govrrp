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
