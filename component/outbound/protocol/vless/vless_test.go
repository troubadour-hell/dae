/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"fmt"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

func TestPassword2Key(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid UUID with dashes",
			password: "550e8400-e29b-41d4-a716-446655440000",
			wantErr:  false,
		},
		{
			name:     "valid UUID without dashes",
			password: "550e8400e29b41d4a716446655440000",
			wantErr:  false,
		},
		{
			name:     "short string mapped to UUID5",
			password: "mypassword",
			wantErr:  false,
		},
		{
			name:     "empty string",
			password: "",
			wantErr:  false, // gets mapped to UUID5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := Password2Key(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Password2Key() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && len(key) != 16 {
				t.Errorf("Password2Key() key length = %d, want 16", len(key))
			}
		})
	}
}

func TestMarshalAddons(t *testing.T) {
	// Empty flow should return nil
	result := marshalAddons("")
	if result != nil {
		t.Errorf("marshalAddons(\"\") = %v, want nil", result)
	}

	// Non-empty flow should produce protobuf bytes
	result = marshalAddons("xtls-rprx-vision")
	if result == nil {
		t.Error("marshalAddons(\"xtls-rprx-vision\") = nil, want non-nil")
	}
	if len(result) != 2+len("xtls-rprx-vision") {
		t.Errorf("marshalAddons length = %d, want %d", len(result), 2+len("xtls-rprx-vision"))
	}
	// Check protobuf tag
	if result[0] != 0x0a {
		t.Errorf("marshalAddons tag = 0x%x, want 0x0a", result[0])
	}
}

func TestNewConn(t *testing.T) {
	// Basic metadata test
	m := Metadata{
		Network: "tcp",
		Flow:    "",
	}
	if networkToByte(m.Network) != 1 {
		t.Errorf("networkToByte(\"tcp\") = %d, want 1", networkToByte(m.Network))
	}
	if networkToByte("udp") != 2 {
		t.Errorf("networkToByte(\"udp\") = %d, want 2", networkToByte("udp"))
	}
	if networkToByte("mux") != 3 {
		t.Errorf("networkToByte(\"mux\") = %d, want 3", networkToByte("mux"))
	}
}

func TestSendHeaderOnce(t *testing.T) {
	// Test that sendHeaderOnce sends the VLESS request header exactly once
	// and that Read triggers header sending before reading the response.

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	metadata := Metadata{
		Network: "tcp",
		Flow:    "",
	}
	metadata.Type = protocol.MetadataTypeIPv4
	metadata.Hostname = "127.0.0.1"
	metadata.Port = 443

	conn, err := NewConn(client, metadata, key)
	if err != nil {
		t.Fatalf("NewConn() error = %v", err)
	}

	// Write+read in a goroutine to avoid blocking
	done := make(chan error, 1)
	go func() {
		// Server side: read the VLESS request header, then send a response header
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			done <- fmt.Errorf("server read error: %w", err)
			return
		}
		// Verify the request header
		if n < 1+16+1+1+2+1+4 { // version + UUID + addons_len + cmd + port + addr_type + IPv4
			done <- fmt.Errorf("request header too short: %d bytes", n)
			return
		}
		if buf[0] != 0 { // version
			done <- fmt.Errorf("unexpected version: %d", buf[0])
			return
		}
		// Send VLESS response header: version(0) + addons_length(0)
		if _, err := server.Write([]byte{0, 0}); err != nil {
			done <- fmt.Errorf("server write error: %w", err)
			return
		}
		// Send some payload data
		if _, err := server.Write([]byte("hello")); err != nil {
			done <- fmt.Errorf("server write payload error: %w", err)
			return
		}
		done <- nil
	}()

	// Client side: Read (without prior Write) should trigger header sending
	readBuf := make([]byte, 1024)
	n, err := conn.Read(readBuf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(readBuf[:n]) != "hello" {
		t.Errorf("Read() = %q, want %q", string(readBuf[:n]), "hello")
	}

	// Wait for server goroutine
	if err := <-done; err != nil {
		t.Fatalf("Server error: %v", err)
	}
}

func TestWriteThenRead(t *testing.T) {
	// Test that Write sends the header with data, and subsequent Read works.

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	metadata := Metadata{
		Network: "tcp",
		Flow:    "",
	}
	metadata.Type = protocol.MetadataTypeDomain
	metadata.Hostname = "example.com"
	metadata.Port = 443

	conn, err := NewConn(client, metadata, key)
	if err != nil {
		t.Fatalf("NewConn() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		// Server side: read the VLESS request header + payload
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			done <- fmt.Errorf("server read error: %w", err)
			return
		}
		// The header should include the payload "request data"
		headerLen := 1 + 16 + 1 + 1 + 2 + 1 + 1 + len("example.com")
		if n != headerLen+len("request data") {
			done <- fmt.Errorf("unexpected request length: got %d, want %d", n, headerLen+len("request data"))
			return
		}
		// Send VLESS response header + payload
		resp := append([]byte{0, 0}, []byte("response data")...)
		if _, err := server.Write(resp); err != nil {
			done <- fmt.Errorf("server write error: %w", err)
			return
		}
		done <- nil
	}()

	// Client side: Write first, then Read
	_, err = conn.Write([]byte("request data"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	readBuf := make([]byte, 1024)
	n, err := conn.Read(readBuf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(readBuf[:n]) != "response data" {
		t.Errorf("Read() = %q, want %q", string(readBuf[:n]), "response data")
	}

	if err := <-done; err != nil {
		t.Fatalf("Server error: %v", err)
	}
}

func TestNoExtraWriteAfterHeader(t *testing.T) {
	// Test that no extra empty writes are sent after the header.
	// This verifies the fix for the time.AfterFunc issue.

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	metadata := Metadata{
		Network: "tcp",
		Flow:    "",
	}
	metadata.Type = protocol.MetadataTypeIPv4
	metadata.Hostname = "10.0.0.1"
	metadata.Port = 80

	conn, err := NewConn(client, metadata, key)
	if err != nil {
		t.Fatalf("NewConn() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		// First read: should get header + "data1"
		n, err := server.Read(buf)
		if err != nil {
			done <- fmt.Errorf("server read 1 error: %w", err)
			return
		}
		headerLen := 1 + 16 + 1 + 1 + 2 + 1 + 4 // version + UUID + addons_len + cmd + port + addr_type + IPv4
		expectedLen := headerLen + len("data1")
		if n != expectedLen {
			done <- fmt.Errorf("first read: got %d bytes, want %d", n, expectedLen)
			return
		}

		// Second read: should get "data2" (no empty frame in between)
		n, err = server.Read(buf)
		if err != nil {
			done <- fmt.Errorf("server read 2 error: %w", err)
			return
		}
		if string(buf[:n]) != "data2" {
			done <- fmt.Errorf("second read: got %q, want %q", string(buf[:n]), "data2")
			return
		}

		done <- nil
	}()

	// Write data1 (sends header + data1)
	if _, err := conn.Write([]byte("data1")); err != nil {
		t.Fatalf("Write(data1) error = %v", err)
	}

	// Write data2 (sends just data2, no extra empty frame)
	if _, err := conn.Write([]byte("data2")); err != nil {
		t.Fatalf("Write(data2) error = %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("Server error: %v", err)
	}
}
