# Lightweight VRRPv3 library
[![CircleCI](https://circleci.com/gh/ep4eg/govrrp.svg?style=svg)](https://circleci.com/gh/ep4eg/govrrp)

This library implements VRRPv3 in accordance with rfc5798

## Installation
Simply run `go get -u github.com/ep4eg/govrrp`

## Example
#### connection
```go
    ...
    // IP addresses we want to advertise
	advertAddresses := []net.IP{
		net.IPv4(192, 165, 55, 55),
		net.IPv4(192, 165, 44, 33),
	}

	// Get default network interface and its IP address. You can define these manually.
	iface, err := govrrp.GetInterface()
	if err != nil {
		// Error handling
	}

	localIPaddr, err := govrrp.GetPrimaryIPv4addr(iface)
	if err != nil {
		// Error handling
	}

	multicastGroup := &net.IPAddr{IP: govrrp.McastGroup}

	// Create socket and listen multicast
	c, err := net.ListenPacket("ip4:"+strconv.Itoa(govrrp.ProtoNumber), multicastGroup.String())
	if err != nil {
		// Error handling
	}

	// Join multicast group. x/net/ipv4 used for simplicity, the same can be implemented with raw sockets.
	p := ipv4.NewPacketConn(c)
	if err != nil {
		// Error handling
	}

	if err := p.JoinGroup(iface, multicastGroup); err != nil {
		// Error handling
	}

	defer func() {
		p.LeaveGroup(iface, multicastGroup)
		p.Close()
	}()
    ...
```

#### Sender
```go
	// Craft VRRP packet
	packet, err := govrrp.NewVRRPpacket(localIPaddr, govrrp.McastGroup, 3, advertAddresses)
	if err != nil {
		// Error handling
	}

	for i := 0; i < 10; i++ {
		// Write the packet to socket
		if _, err := p.WriteTo(packet, nil, multicastGroup); err != nil {
			panic(err)
		}
		time.Sleep(1 * time.Second)
    }
    
```
#### Reciever
```go
	for {
		// Writing the entire packet to the socket
		buf := make([]byte, 1500)
		rLen, _, _, err := p.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		msg := govrrp.Message{}
		msg.Unmarshal(buf[:rLen])
		fmt.Printf("Advertised IP addresses: %v\n", msg.IPv4addresses)
	}
```