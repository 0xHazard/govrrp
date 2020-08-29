# Lightweight VRRPv3 library
[![CircleCI](https://circleci.com/gh/ep4eg/govrrp.svg?style=svg)](https://circleci.com/gh/ep4eg/govrrp)

This library implenents VRRPv3 according to rfc5798

## Installation
Simply run `go get -u golang.org/x/net`

## Sender example
```go
    ...
    multicastGroup := &net.IPAddr{IP: net.ParseIP(govrrp.VRRPipv4MulticastAddr)}
    advertAddresses := []net.IP{net.IPv4(192, 165, 55, 55), net.IPv4(192, 165, 44, 33)}

    // Getting default network interface and its IP address. You can define these manually.
    iface, err := govrrp.GetInterface()
    if err != nil {
        // Error handling
    }

    localIPaddr, err := govrrp.GetPrimaryIPv4addr(iface)
    if err != nil {
        // Error handling
    }

    // Creating a socket and joining the multicast group.
    c, err := net.ListenPacket("ip4:112", localIPaddr.String())
    if err != nil {
        log.Fatal(err)
    }
    r, err := ipv4.NewRawConn(c)
    if err != nil {
        // Error handling
    }

    if err := r.JoinGroup(iface, multicastGroup); err != nil {
        // Error handling
    }

    defer func() {
        r.LeaveGroup(iface, multicastGroup)
        r.Close()
    }()
    ...

    // Generating VRRP message.
    packet, err := govrrp.NewVRRPmulticastPacket(iface, 1, advertAddresses)
    if err != nil {
        // Error handling
    }

    // Writing the entire packet to the socket
    if err := r.WriteTo(packet.IPv4header, packet.VRRPpacket.Header, packet.ControlMessage); err != nil {
        // Error handling
    }
    ...
```

## Reciever example
```go
    multicastGroup := &net.IPAddr{IP: net.ParseIP(govrrp.VRRPipv4MulticastAddr)}

    // Getting default network interface.
    iface, err := govrrp.GetInterface()
    if err != nil {
        // Error handling
    }

    // Creating a socket and joining the multicast group.
    c, err := net.ListenPacket("ip4:112", govrrp.VRRPipv4MulticastAddr)
    if err != nil {
        // Error handling
    }
    r, err := ipv4.NewRawConn(c)
    if err != nil {
        // Error handling
    }
        defer func() {
        r.LeaveGroup(iface, multicastGroup)
        r.Close()
    }()
    ...

        b := make([]byte, 1500)
    for {
        r.SetControlMessage(ipv4.FlagDst, true)
        packet, vrrp, cm, err := r.ReadFrom(b)
        if err != nil {
            // Error handling
        }

        vrrpMessage := govrrp.VRRPmessage{}
        vrrpMessage.Unmarshal(vrrp)
        ...

        fmt.Printf("%v\n", cm)
        fmt.Printf("%v\n", vrrpMessage)
    }
```
