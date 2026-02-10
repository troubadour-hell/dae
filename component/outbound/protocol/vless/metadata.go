/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/protocol"
)

type Metadata struct {
	protocol.Metadata
	Network string
	Flow    string
	Mux     bool
}

func parseMetadataType(t byte) protocol.MetadataType {
	switch t {
	case 1:
		return protocol.MetadataTypeIPv4
	case 2:
		return protocol.MetadataTypeDomain
	case 3:
		return protocol.MetadataTypeIPv6
	case 4:
		return protocol.MetadataTypeMsg
	default:
		return protocol.MetadataTypeInvalid
	}
}

func metadataTypeToByte(typ protocol.MetadataType) byte {
	switch typ {
	case protocol.MetadataTypeIPv4:
		return 1
	case protocol.MetadataTypeDomain:
		return 2
	case protocol.MetadataTypeIPv6:
		return 3
	case protocol.MetadataTypeMsg:
		return 4
	default:
		return 0
	}
}

func networkToByte(network string) byte {
	switch network {
	case "tcp":
		return 1
	case "udp":
		return 2
	case "mux":
		return 3
	default:
		return 0
	}
}

func (m *Metadata) addrLen() int {
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		return 4
	case protocol.MetadataTypeIPv6:
		return 16
	case protocol.MetadataTypeDomain:
		return 1 + len([]byte(m.Hostname))
	case protocol.MetadataTypeMsg:
		return 1
	default:
		return 0
	}
}

func (m *Metadata) putAddr(dst []byte) int {
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		copy(dst, net.ParseIP(m.Hostname).To4()[:4])
		return 4
	case protocol.MetadataTypeIPv6:
		copy(dst, net.ParseIP(m.Hostname)[:16])
		return 16
	case protocol.MetadataTypeDomain:
		dst[0] = byte(len([]byte(m.Hostname)))
		copy(dst[1:], m.Hostname)
		return 1 + int(dst[0])
	case protocol.MetadataTypeMsg:
		dst[0] = byte(m.Cmd)
		return 1
	default:
		return 0
	}
}

var errInvalidMetadata = fmt.Errorf("invalid metadata")
