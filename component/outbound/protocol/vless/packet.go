/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// PacketConn wraps a VLESS Conn for length-prefixed UDP packets.
type PacketConn struct {
	*Conn
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	bLen := make([]byte, 2)
	if _, err = io.ReadFull(&readWrapper{readFunc: c.read}, bLen); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(bLen))
	if len(p) < length {
		return 0, nil, fmt.Errorf("buf size is not enough")
	}
	n, err = io.ReadFull(&readWrapper{readFunc: c.read}, p[:length])
	return n, c.RemoteAddr(), err
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	bLen := make([]byte, 2)
	binary.BigEndian.PutUint16(bLen, uint16(len(p)))
	if _, err = c.write(bLen); err != nil {
		return 0, err
	}
	return c.write(p)
}

// XUDPPacketConn wraps a VLESS Conn for XUDP multiplexed packets (used with Vision flow).
type XUDPPacketConn struct {
	*Conn
	needHandshake bool
}

func (pc *XUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read frame length (2 bytes)
	var frameLengthBytes [2]byte
	if _, err = io.ReadFull(pc.Conn, frameLengthBytes[:]); err != nil {
		return 0, nil, err
	}
	frameLength := binary.BigEndian.Uint16(frameLengthBytes[:])

	// Read frame header (4 bytes)
	var frameHeaderBytes [4]byte
	if _, err = io.ReadFull(pc.Conn, frameHeaderBytes[:]); err != nil {
		return 0, nil, err
	}

	switch frameHeaderBytes[2] {
	case 0x01:
		return 0, nil, fmt.Errorf("unexpected frame new")
	case 0x02:
		// Keep
		if frameLength > 4 {
			addrData := make([]byte, frameLength-4)
			if _, err = io.ReadFull(pc.Conn, addrData); err != nil {
				return 0, nil, err
			}
			addrPort, err := readPacketAddr(addrData)
			if err != nil {
				return 0, nil, err
			}
			addr = net.UDPAddrFromAddrPort(addrPort)
		}
	case 0x03:
		return 0, nil, io.EOF
	case 0x04:
		// KeepAlive
	default:
		return 0, nil, fmt.Errorf("unsupported frame header: %x", frameHeaderBytes[2])
	}

	if frameHeaderBytes[3]&1 != 1 {
		return pc.ReadFrom(p)
	}

	// Read length and payload
	var lengthBytes [2]byte
	if _, err = io.ReadFull(pc.Conn, lengthBytes[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint16(lengthBytes[:])

	if length > uint16(len(p)) {
		return 0, nil, fmt.Errorf("buffer too small")
	}

	n, err = io.ReadFull(pc.Conn, p[:length])
	return n, addr, err
}

func (pc *XUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var addrPort netip.AddrPort
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		addrPort = udpAddr.AddrPort()
	} else {
		ap, parseErr := netip.ParseAddrPort(addr.String())
		if parseErr != nil {
			return 0, parseErr
		}
		addrPort = ap
	}

	packetAddrLen := ipAddrToPacketAddrLength(addrPort)
	prefix := make([]byte, 7+packetAddrLen)
	if err := putPacketAddr(prefix[7:], addrPort); err != nil {
		return 0, err
	}

	l := len(prefix) - 2
	if !pc.needHandshake {
		pc.needHandshake = true
		prefix[0] = byte(l >> 8)
		prefix[1] = byte(l)
		prefix[2] = 0
		prefix[3] = 0
		prefix[4] = 1 // new
		prefix[5] = 1 // option
		prefix[6] = 2 // udp
	} else {
		prefix[0] = byte(l >> 8)
		prefix[1] = byte(l)
		prefix[2] = 0
		prefix[3] = 0
		prefix[4] = 2 // keep
		prefix[5] = 1 // option
		prefix[6] = 2 // udp
	}

	dataLen := len(p)
	buf := make([]byte, 0, len(prefix)+2+dataLen)
	buf = append(buf, prefix...)
	buf = append(buf, byte(dataLen>>8), byte(dataLen))
	buf = append(buf, p...)

	_, err = pc.Conn.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func ipAddrToPacketAddrLength(addr netip.AddrPort) int {
	nip, ok := netip.AddrFromSlice(addr.Addr().AsSlice())
	if !ok {
		return 0
	}
	if nip.Is4() {
		return 1 + 4 + 2
	}
	return 1 + 16 + 2
}

func putPacketAddr(src []byte, addr netip.AddrPort) error {
	nip, ok := netip.AddrFromSlice(addr.Addr().AsSlice())
	if !ok {
		return fmt.Errorf("invalid IP")
	}
	if nip.Is4() {
		binary.BigEndian.PutUint16(src[0:2], addr.Port())
		src[2] = 1
		copy(src[3:7], nip.AsSlice())
	} else {
		binary.BigEndian.PutUint16(src[0:2], addr.Port())
		src[2] = 3
		copy(src[3:19], nip.AsSlice())
	}
	return nil
}

func readPacketAddr(p []byte) (addr netip.AddrPort, err error) {
	p = p[1:]
	port := binary.BigEndian.Uint16(p[0:2])
	ipType := p[2]
	ip := p[3:]
	if ipType == 1 {
		ip = ip[:4]
	} else {
		ip = ip[:16]
	}
	ipAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("invalid IP")
	}
	return netip.AddrPortFrom(ipAddr, port), nil
}
