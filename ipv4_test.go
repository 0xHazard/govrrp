package govrrp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVRRPmulticastPacket(t *testing.T) {
	iface, err := GetInterface()
	require.NoError(t, err)

	tests := []struct {
		name      string
		iface     *net.Interface
		addresses []net.IP
		expect    bool
	}{
		{"Valid case", iface, []net.IP{net.IPv4(192, 168, 8, 99).To4(), net.IPv4(172, 23, 44, 6).To4()}, true},
		{"IPv6 check", iface, []net.IP{net.ParseIP("ff02::114")}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewIPmulticastPacket(tc.iface, 2, tc.addresses)
			if err != nil {
				require.Equal(t, tc.expect, false)
				return
			}
			// TODO ...
			// just a placeholder for now
			assert.Equal(t, tc.expect, true)
		})
	}
}
