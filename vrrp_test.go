package govrrp

import (
	"bytes"
	"testing"
)

func TestAddIPaddresses(t *testing.T) {

	type addresses struct {
		addr   [][]byte
		count  int
		result bool
	}

	addrTable := []addresses{
		addresses{[][]byte{[]byte{192, 168, 8, 99}, []byte{172, 23, 44, 6}}, 2, true},
		addresses{[][]byte{[]byte{192, 168, 8, 0}, []byte{192, 168, 8, 6}}, 2, false},
		addresses{[][]byte{[]byte{172, 22, 2, 55}, []byte{172, 22, 2, 2}, []byte{192, 168, 3, 1}, []byte{192, 160, 6, 56}}, 4, true},
		addresses{[][]byte{[]byte{0, 168, 8, 99}}, 1, false},
		addresses{[][]byte{[]byte{0, 0, 0, 0}}, 1, false},
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
		IPv4addresses: [][]byte{[]byte{172, 22, 2, 55}, []byte{192, 168, 3, 1}},
		CountIPv4:     2,
	}

	packet, err := testMessage.Marshal()
	if err != nil {
		t.Errorf("FAILED: %v\n", err)
	}

	var testAddr []byte
	for _, addr := range testMessage.IPv4addresses {
		testAddr = append(testAddr, addr...)
	}

	if bytes.Equal(packet.Header[8:], testAddr) {
		t.Logf("PASSED: %v\n", testMessage.IPv4addresses)
	} else {
		t.Errorf("FAILED: got %v; want %v\n", packet.Header[8:], testAddr)
	}

	if int(packet.Header[3]) == testMessage.CountIPv4 {
		t.Logf("PASSED: %v\n", testMessage.CountIPv4)
	} else {
		t.Errorf("FAILED: got %d; want %d\n", packet.Header[3], testMessage.CountIPv4)
	}
}
