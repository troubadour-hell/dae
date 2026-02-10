/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"context"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

const (
	XRV = "xtls-rprx-vision"
)

func init() {
	protocol.Register("vless", NewDialer)
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress string
	flow         string
	key          []byte
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	id, err := Password2Key(header.Password)
	if err != nil {
		return nil, err
	}
	flow, _ := header.Feature1.(string)
	switch flow {
	case XRV, "":
	default:
		return nil, fmt.Errorf("unsupported xtls flow type: %v", flow)
	}
	return &Dialer{
		StatelessDialer: protocol.StatelessDialer{
			ParentDialer: nextDialer,
		},
		proxyAddress: header.ProxyAddress,
		flow:         flow,
		key:          id,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
		if err != nil {
			return nil, err
		}
		vlessConn, err := NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  "tcp",
			Flow:     d.flow,
			Mux:      false,
		}, d.key)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return vlessConn, nil
	case "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
		if err != nil {
			return nil, err
		}
		mux := d.flow == XRV
		vlessConn, err := NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  "udp",
			Flow:     d.flow,
			Mux:      mux,
		}, d.key)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if mux {
			return &netproxy.BindPacketConn{
				PacketConn: &XUDPPacketConn{Conn: vlessConn},
				Address:    netproxy.NewAddr("udp", addr),
			}, nil
		}
		return &netproxy.BindPacketConn{
			PacketConn: &PacketConn{Conn: vlessConn},
			Address:    netproxy.NewAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return nil, err
	}
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	mux := d.flow == XRV
	vlessConn, err := NewConn(conn, Metadata{
		Metadata: mdata,
		Network:  "udp",
		Flow:     d.flow,
		Mux:      mux,
	}, d.key)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if mux {
		return &XUDPPacketConn{Conn: vlessConn}, nil
	}
	return &PacketConn{Conn: vlessConn}, nil
}
