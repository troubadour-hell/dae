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
	"sync"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

type Conn struct {
	net.Conn
	metadata Metadata
	cmdKey   []byte

	writeMutex sync.Mutex
	readMutex  sync.Mutex
	onceWrite  bool
	onceRead   sync.Once
	readErr    error

	addonsBytes []byte
}

func NewConn(conn net.Conn, metadata Metadata, cmdKey []byte) (c *Conn, err error) {
	key := make([]byte, len(cmdKey))
	copy(key, cmdKey)
	c = &Conn{
		Conn:     conn,
		metadata: metadata,
		cmdKey:   key,
	}
	if metadata.Network == "tcp" {
		time.AfterFunc(100*time.Millisecond, func() {
			// avoid the situation where the server sends messages first
			if _, err = c.Write(nil); err != nil {
				return
			}
		})
	}
	if metadata.Flow != "" {
		c.addonsBytes = marshalAddons(metadata.Flow)
	}
	return c, nil
}

// marshalAddons manually encodes the Addons protobuf message.
// message Addons { string Flow = 1; }
func marshalAddons(flow string) []byte {
	if flow == "" {
		return nil
	}
	// Protobuf: field 1, wire type 2 (length-delimited) = tag 0x0a
	data := make([]byte, 0, 2+len(flow))
	data = append(data, 0x0a, byte(len(flow)))
	data = append(data, flow...)
	return data
}

func (c *Conn) reqHeaderFromPool(payload []byte) []byte {
	addrLen := c.metadata.addrLen()
	var bufSize int
	if !c.metadata.Mux {
		bufSize = 1 + 16 + len(c.addonsBytes) + 1 + 1 + 2 + 1 + addrLen + len(payload)
	} else {
		bufSize = 1 + 16 + len(c.addonsBytes) + 1 + 1 + len(payload)
	}
	buf := pool.GetBuffer(bufSize)
	start := 0
	buf[start] = 0 // version
	start++
	copy(buf[start:], c.cmdKey)
	start += 16
	buf[start] = byte(len(c.addonsBytes))
	start++
	copy(buf[start:], c.addonsBytes)
	start += len(c.addonsBytes)
	if !c.metadata.Mux {
		buf[start] = networkToByte(c.metadata.Network)
		start++
		binary.BigEndian.PutUint16(buf[start:], c.metadata.Port)
		start += 2
		buf[start] = metadataTypeToByte(c.metadata.Type)
		start++
		c.metadata.putAddr(buf[start:])
		start += addrLen
	} else {
		buf[start] = networkToByte("mux")
		start++
	}
	copy(buf[start:], payload)
	return buf[:bufSize]
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.metadata.Network == "udp" && c.metadata.Flow != XRV {
		bLen := make([]byte, 2)
		binary.BigEndian.PutUint16(bLen, uint16(len(b)))
		if _, err = c.write(bLen); err != nil {
			return 0, err
		}
	}
	return c.write(b)
}

func (c *Conn) write(b []byte) (n int, err error) {
	if !c.onceWrite {
		buf := c.reqHeaderFromPool(b)
		defer pool.PutBuffer(buf)
		if _, err = c.Conn.Write(buf); err != nil {
			return 0, fmt.Errorf("write header: %w", err)
		}
		c.onceWrite = true
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.metadata.Network == "udp" && c.metadata.Flow != XRV {
		bLen := make([]byte, 2)
		if _, err = io.ReadFull(&readWrapper{readFunc: c.read}, bLen); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(bLen))
		if len(b) < length {
			return 0, fmt.Errorf("buf size is not enough")
		}
	}

	return c.read(b)
}

func (c *Conn) read(b []byte) (n int, err error) {
	c.onceRead.Do(func() {
		c.readErr = c.readRespHeader()
	})
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(b)
}

func (c *Conn) readRespHeader() error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		return fmt.Errorf("version %v is not supported", buf[0])
	}
	if _, err := io.CopyN(io.Discard, c.Conn, int64(buf[1])); err != nil {
		return err
	}
	return nil
}

type readWrapper struct {
	readFunc func([]byte) (int, error)
}

func (r *readWrapper) Read(p []byte) (int, error) {
	return r.readFunc(p)
}
