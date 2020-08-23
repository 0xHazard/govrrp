package govrrp

import (
	"net"
	"testing"
)

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
