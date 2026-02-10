/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"testing"
)

func TestParseVlessURL(t *testing.T) {
	tests := []struct {
		name    string
		link    string
		wantErr bool
		checks  func(t *testing.T, v *Vless)
	}{
		{
			name: "basic vless tcp tls",
			link: "vless://uuid-here@example.com:443?type=tcp&security=tls&sni=example.com#test-node",
			checks: func(t *testing.T, v *Vless) {
				if v.Server != "example.com" {
					t.Errorf("Server = %v, want example.com", v.Server)
				}
				if v.Port != 443 {
					t.Errorf("Port = %v, want 443", v.Port)
				}
				if v.ID != "uuid-here" {
					t.Errorf("ID = %v, want uuid-here", v.ID)
				}
				if v.Net != "tcp" {
					t.Errorf("Net = %v, want tcp", v.Net)
				}
				if v.TLS != "tls" {
					t.Errorf("TLS = %v, want tls", v.TLS)
				}
				if v.SNI != "example.com" {
					t.Errorf("SNI = %v, want example.com", v.SNI)
				}
				if v.Name != "test-node" {
					t.Errorf("Name = %v, want test-node", v.Name)
				}
			},
		},
		{
			name: "vless ws",
			link: "vless://uuid-here@example.com:443?type=ws&security=tls&path=/ws&host=cdn.example.com&sni=example.com#ws-node",
			checks: func(t *testing.T, v *Vless) {
				if v.Net != "ws" {
					t.Errorf("Net = %v, want ws", v.Net)
				}
				if v.Path != "/ws" {
					t.Errorf("Path = %v, want /ws", v.Path)
				}
				if v.Host != "cdn.example.com" {
					t.Errorf("Host = %v, want cdn.example.com", v.Host)
				}
			},
		},
		{
			name: "vless with vision flow",
			link: "vless://uuid-here@example.com:443?type=tcp&security=tls&flow=xtls-rprx-vision&sni=example.com#vision-node",
			checks: func(t *testing.T, v *Vless) {
				if v.Flow != "xtls-rprx-vision" {
					t.Errorf("Flow = %v, want xtls-rprx-vision", v.Flow)
				}
			},
		},
		{
			name: "vless with reality",
			link: "vless://uuid-here@example.com:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=publickey&sid=shortid&spx=%2F#reality-node",
			checks: func(t *testing.T, v *Vless) {
				if v.TLS != "reality" {
					t.Errorf("TLS = %v, want reality", v.TLS)
				}
				if v.PublicKey != "publickey" {
					t.Errorf("PublicKey = %v, want publickey", v.PublicKey)
				}
				if v.ShortId != "shortid" {
					t.Errorf("ShortId = %v, want shortid", v.ShortId)
				}
			},
		},
		{
			name: "vless grpc",
			link: "vless://uuid-here@example.com:443?type=grpc&security=tls&serviceName=myservice&sni=example.com#grpc-node",
			checks: func(t *testing.T, v *Vless) {
				if v.Net != "grpc" {
					t.Errorf("Net = %v, want grpc", v.Net)
				}
				if v.ServiceName != "myservice" {
					t.Errorf("ServiceName = %v, want myservice", v.ServiceName)
				}
			},
		},
		{
			name: "defaults when no type/security",
			link: "vless://uuid-here@example.com:443#default-node",
			checks: func(t *testing.T, v *Vless) {
				if v.Net != "tcp" {
					t.Errorf("Net = %v, want tcp (default)", v.Net)
				}
				if v.TLS != "none" {
					t.Errorf("TLS = %v, want none (default)", v.TLS)
				}
				if v.Type != "none" {
					t.Errorf("Type = %v, want none (default)", v.Type)
				}
			},
		},
		{
			name:    "invalid URL",
			link:    "not-a-valid-url://::::",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseVlessURL(tt.link)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVlessURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && tt.checks != nil {
				tt.checks(t, v)
			}
		})
	}
}

func TestExportToURL(t *testing.T) {
	link := "vless://uuid-here@example.com:443?type=tcp&security=tls&sni=example.com#test-node"
	v, err := ParseVlessURL(link)
	if err != nil {
		t.Fatal(err)
	}
	exported := v.ExportToURL()
	// Re-parse the exported URL
	v2, err := ParseVlessURL(exported)
	if err != nil {
		t.Fatalf("failed to re-parse exported URL: %v", err)
	}
	if v2.Server != v.Server || v2.Port != v.Port || v2.ID != v.ID || v2.Net != v.Net || v2.TLS != v.TLS {
		t.Errorf("exported URL doesn't round-trip correctly")
	}
}
