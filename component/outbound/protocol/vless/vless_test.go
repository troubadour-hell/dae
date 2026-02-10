/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"testing"
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
